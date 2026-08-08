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
SOURCE_PROXY = "proxy"               # asserted, but vouched for by a trusted hop
SOURCE_NONE = "none"                 # absent

#: Sources where the value was proven cryptographically rather than claimed.
#:
#: SOURCE_PROXY is deliberately absent. The trusted proxy proved *the hop* with
#: a shared secret; it did not prove the end user's credential to Shield. Adding
#: it here would make ``role_verified`` mean two different things and would
#: silently promote a vouched role to a proven one in every audit built on it.
VERIFIED_SOURCES = frozenset({SOURCE_AGENT_TOKEN, SOURCE_MTLS, SOURCE_OIDC})

#: Token binding (proof-of-possession). Separate from role binding: one asks
#: "what role", the other "is the presenter the party this was issued to".
BIND_OFF, BIND_OPTIONAL, BIND_REQUIRED = "off", "optional", "required"
_BIND_MODES = (BIND_OFF, BIND_OPTIONAL, BIND_REQUIRED)
_BIND_ENV = "SHIELD_TOKEN_BINDING"

#: Outcome of the binding check, recorded on every decision.
BINDING_OFF = "off"            # not enabled
BINDING_UNBOUND = "unbound"    # credential carries no cnf
BINDING_VERIFIED = "verified"  # proof presented and valid
BINDING_FAILED = "failed"      # bound token, proof missing or invalid


def token_binding_mode() -> str:
    """off | optional | required — default off.

    ``optional`` verifies a proof when the token is bound and records the
    result, denying nothing. ``required`` refuses a bound token without a valid
    proof. Off costs nothing: no header is read and no crypto runs.
    """
    v = os.environ.get(_BIND_ENV, BIND_OFF).strip().lower()
    return v if v in _BIND_MODES else BIND_OFF


def _request_uri(request: Any) -> str:
    """The htu comparison target.

    Behind a load balancer the scheme and host the client used are in
    X-Forwarded-*, and the raw URL says http://internal-host. Trust those
    headers ONLY when the proxy boundary says the hop is trusted — otherwise a
    caller picks its own htu and the check means nothing.
    """
    try:
        url = str(request.url)
    except Exception:
        return ""
    try:
        from core.proxy_trust import peer_is_trusted, trusted_proxy_only
        if trusted_proxy_only() and peer_is_trusted(request):
            from urllib.parse import urlsplit, urlunsplit
            proto = _header(request, "X-Forwarded-Proto")
            host = _header(request, "X-Forwarded-Host")
            if proto or host:
                p = urlsplit(url)
                url = urlunsplit((proto or p.scheme, host or p.netloc, p.path, "", ""))
    except Exception:
        pass
    return url


def verify_token_binding(request: Any, claims: Optional[dict]) -> tuple:
    """(status, reason) for the credential on this request.

    Never raises: a binding check that 500s on the guard path is worse than one
    that reports failure and lets the caller decide.
    """
    mode = token_binding_mode()
    if mode == BIND_OFF:
        return BINDING_OFF, ""
    try:
        from core import dpop
        jkt = dpop.cnf_jkt(claims or {})
        if not jkt:
            return BINDING_UNBOUND, ""
        proof = _header(request, "DPoP")
        if not proof:
            return BINDING_FAILED, "bound token presented without a DPoP proof"
        p = dpop.verify_proof(
            proof, expected_jkt=jkt,
            http_method=getattr(request, "method", "") or "",
            http_uri=_request_uri(request),
        )
        if not dpop.claim_jti(p.jti, 60):
            return BINDING_FAILED, "DPoP proof replayed"
        return BINDING_VERIFIED, ""
    except Exception as e:
        return BINDING_FAILED, str(e)


MODE_OFF, MODE_PREFER, MODE_STRICT = "off", "prefer", "strict"

#: ``strict``, except a self-asserted role is accepted from a request that came
#: through the trusted-proxy boundary. For a deployment where Shield is public
#: but internal callers legitimately send X-User-Role: strict alone breaks them,
#: and prefer leaves the header forgeable by anyone on the internet.
#: See docs/spec-proxy-trusted-role-header.md.
MODE_STRICT_PROXY = "strict_proxy"

_MODES = (MODE_OFF, MODE_PREFER, MODE_STRICT, MODE_STRICT_PROXY)

#: Modes that prefer a verified claim over anything self-asserted.
_CLAIM_FIRST_MODES = (MODE_PREFER, MODE_STRICT, MODE_STRICT_PROXY)

#: Modes that refuse a self-asserted role absent some other warrant.
_REFUSING_MODES = (MODE_STRICT, MODE_STRICT_PROXY)

_ENV = "SHIELD_ROLE_BINDING"


def _env_mode() -> str:
    v = os.environ.get(_ENV, MODE_OFF).strip().lower()
    return v if v in _MODES else MODE_OFF


def _stored_config(tenant_id: Optional[str]) -> Optional[dict]:
    """Per-tenant stored config, via the cache in storage.role_binding_config.

    Guarded: the module is absent from slim images that do not COPY it, and a
    missing optional module must degrade to env defaults rather than raise on
    the guard path.
    """
    try:
        from storage.role_binding_config import get_config
        return get_config(tenant_id)
    except Exception:
        return None


def role_binding_mode(tenant_id: Optional[str] = None) -> str:
    """off | prefer | strict | strict_proxy — default off.

    ``SHIELD_ROLE_BINDING=off`` disables the feature globally regardless of
    tenant config: the operator kill switch, checked before any store read so
    a deployment with binding off performs ZERO Redis reads on the guard path.
    Otherwise a tenant setting wins.

    A store that is unreachable resolves to the env default rather than locking
    out every tenant on a Redis blip — the failure mode of "cannot read config"
    should not be "deny everything".
    """
    env = _env_mode()
    if env == MODE_OFF or not tenant_id:
        return env
    stored = _stored_config(tenant_id)
    if stored:
        cand = str(stored.get("mode", "")).strip().lower()
        if cand in _MODES:
            return cand
    return env


def role_binding_config(tenant_id: Optional[str] = None) -> dict:
    """Mode plus the claim path and role rename map for this tenant.

    ``role_claim`` supports a dotted path, because IdPs nest it: Keycloak puts
    realm roles at ``realm_access.roles``, Okta uses ``groups``, Entra ``roles``.

    One store read backs all three fields. This previously issued a second,
    uncached GET on the same key for the claim path — harmless only while the
    config was unreachable, and a synchronous Redis round trip per guarded
    request the moment it became live.
    """
    from storage.role_binding_config import DEFAULT_ROLE_CLAIM

    env = _env_mode()
    cfg = {"mode": env, "role_claim": DEFAULT_ROLE_CLAIM, "role_map": {}}
    if env == MODE_OFF or not tenant_id:
        return cfg

    stored = _stored_config(tenant_id)
    if not stored:
        return cfg

    cand = str(stored.get("mode", "")).strip().lower()
    if cand in _MODES:
        cfg["mode"] = cand
    if stored.get("role_claim"):
        cfg["role_claim"] = str(stored["role_claim"])
    if isinstance(stored.get("role_map"), dict):
        cfg["role_map"] = stored["role_map"]
    return cfg


def _dotted(claims: dict, path: str):
    """Read a possibly-nested claim. Returns None rather than raising."""
    cur: Any = claims
    for part in (path or "").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def extract_roles(claims: dict, role_claim: str, role_map: Optional[dict] = None) -> tuple:
    """Roles from a set of VERIFIED claims, in a stable order.

    Accepts a list or a single string, since IdPs differ. Order is preserved as
    issued — never set iteration, or the same token would authorize differently
    between calls.
    """
    val = _dotted(claims or {}, role_claim)
    if val is None:
        return ()
    raw = [val] if isinstance(val, str) else list(val) if isinstance(val, (list, tuple)) else []
    mapping = role_map or {}
    out, seen = [], set()
    for r in raw:
        name = str(mapping.get(str(r), r)).strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return tuple(out)


def _workload_roles(request: Any, cfg: dict) -> tuple:
    """Roles from a verified workload identity (OIDC service account, SPIFFE).

    Resolved lazily and only when binding is on, so a deployment with binding
    off pays nothing — no provider chain, no JWKS lookup, on the guard path.
    """
    wi = getattr(getattr(request, "state", None), "workload_identity", None)
    if wi is None:
        try:
            from core.workload_identity import resolve_workload_identity
            wi = resolve_workload_identity(request)
        except Exception:
            return ()
    if wi is None:
        return ()
    return extract_roles(getattr(wi, "claims", {}) or {},
                         cfg.get("role_claim", ""), cfg.get("role_map"))


def clear_role_binding_cache_for_tests() -> None:
    try:
        from storage.role_binding_config import clear_cache_for_tests
        clear_cache_for_tests()
    except Exception:
        pass


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
    #: The role-binding mode this decision resolved under.
    mode: str = "off"
    #: Token-binding outcome: off | unbound | verified | failed.
    binding: str = BINDING_OFF
    binding_error: str = ""
    #: Delegation — the user this agent is acting for, when proven.
    acting_for: str = ""
    delegation_verified: bool = False
    delegation_error: str = ""

    @property
    def agent_verified(self) -> bool:
        return self.agent_source in VERIFIED_SOURCES

    @property
    def role_verified(self) -> bool:
        """True only when the role came from a verified credential's claim."""
        return self.role_source in VERIFIED_SOURCES

    @property
    def delegated(self) -> bool:
        """A verified user is being acted for.

        Authorization then intersects the agent's grant with this user's role —
        the tool allowlist already enforces agent AND role, so taking the role
        from a verified token is what makes that intersection meaningful.
        """
        return self.delegation_verified and bool(self.acting_for)

    @property
    def binding_failed(self) -> bool:
        """A bound credential whose proof was missing, invalid or replayed.

        In ``required`` mode the caller must refuse the request. This is the
        stolen-token case.
        """
        return self.binding == BINDING_FAILED

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
            "token_binding": self.binding,
            "acting_for": self.acting_for,
            "delegation_verified": self.delegation_verified,
            **({"delegation_error": self.delegation_error} if self.delegation_error else {}),
            **({"binding_error": self.binding_error} if self.binding_error else {}),
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


def _tenant_of(request: Any) -> str:
    """The tenant this request authenticated as, for per-tenant config lookup.

    Reads ONLY ``request.state.tenant_id`` — set by the tenant API-key auth in
    core/auth.py and core/middleware.py after the key is verified.

    The ``X-Tenant-ID`` header is deliberately NOT consulted, even though other
    call sites accept it for their own purposes. Role-binding config decides
    which claim path is read and how IdP groups map to Shield roles; letting a
    caller name the tenant whose mapping applies would let it pick a config that
    maps its own groups onto another tenant's privileged role. Config selection
    must follow authentication, not assertion.

    Returns "" when no authenticated tenant is present, which resolves to the
    env default — the behaviour every deployment has today.
    """
    state = getattr(request, "state", None)
    if state is None:
        return ""
    return str(getattr(state, "tenant_id", "") or "")


def _proxy_vouched(request: Any) -> bool:
    """True only when the trusted-proxy boundary is ON and this peer passed it.

    Both halves are required. Without ``trusted_proxy_only()`` an operator could
    set ``strict_proxy`` while the boundary is disabled and get ``strict``
    semantics under a name that promises otherwise — the mode would look
    configured and do nothing.

    Any failure is False: boundary off, module missing, exception. A role that
    cannot be attributed to a trusted hop is not a role. Imported lazily so a
    deployment on any other mode never loads the module on the guard path.
    """
    try:
        from core.proxy_trust import peer_is_trusted, trusted_proxy_only
        return bool(trusted_proxy_only() and peer_is_trusted(request))
    except Exception:
        return False


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

    ``tenant_id`` selects the per-tenant role-binding config. When not passed it
    is resolved from the request's *authenticated* tenant. Resolving it here
    rather than at each call site is deliberate: the config was unreachable in
    production for exactly one reason — every one of the seven call sites
    omitted it — and a rule that each new route must remember to pass it would
    reintroduce that the next time a route is added.
    """
    ident = _verified_identity(request)
    if not tenant_id:
        tenant_id = _tenant_of(request)

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
    # Delegation: which user is this agent acting for. Off by default and
    # short-circuits before reading any header.
    try:
        from core.delegation import resolve_delegation
        deleg = resolve_delegation(request)
    except Exception:
        deleg = None

    cfg = role_binding_config(tenant_id)
    mode = cfg["mode"]

    # Proof-of-possession. Independent of role binding: a token can be bound
    # without carrying a role, and vice versa. Off by default and short-circuits
    # before reading any header.
    wi = getattr(getattr(request, "state", None), "workload_identity", None)
    binding, binding_error = verify_token_binding(
        request, getattr(wi, "claims", None) if wi is not None else None)
    claimed = tuple(getattr(ident, "roles", ()) or ()) if ident is not None else ()

    # A verified delegated user is used regardless of the role-binding mode.
    # Delegation has its own switch (SHIELD_DELEGATION); requiring a second,
    # unrelated flag to make it take effect would be a footgun — an operator who
    # turns delegation on means the user's authority to apply.
    if deleg is not None and deleg.verified and deleg.user_roles:
        user_role = str(deleg.user_roles[0])
        role_source = SOURCE_OIDC
        return ResolvedIdentity(
            agent_key=agent_key, agent_source=agent_source,
            user_role=user_role, role_source=role_source,
            identity_method=identity_method, trust_level=trust_level,
            claimed_roles=tuple(deleg.user_roles), mode=mode,
            binding=binding, binding_error=binding_error,
            acting_for=deleg.user_sub, delegation_verified=True,
            delegation_error="",
        )

    # Where the ROLE was proven, which is not always where the agent key came
    # from. Borrowing agent_source for both reported role_source="header" for a
    # role read out of a verified OIDC credential whenever the agent key had
    # arrived in a header — understating the role's provenance, and silently
    # disabling header_overridden, since that keys off role_verified.
    claim_source = agent_source if claimed else SOURCE_NONE

    if not claimed and mode in _CLAIM_FIRST_MODES:
        # No role on the agent token — try a verified external credential.
        wl = _workload_roles(request, cfg)
        if wl:
            claimed = wl
            # Proven by the workload credential's signature, regardless of how
            # the agent key was presented.
            claim_source = SOURCE_OIDC
            if agent_source == SOURCE_NONE:
                agent_source = SOURCE_OIDC
    if claimed and mode in _CLAIM_FIRST_MODES:
        # The claim wins and the header is ignored. Deterministic ordering: the
        # first role as issued, never set iteration.
        user_role, role_source = str(claimed[0]), claim_source
    elif mode == MODE_STRICT_PROXY and _proxy_vouched(request):
        # A self-asserted role, but from a hop that proved itself with a shared
        # secret. Recorded as SOURCE_PROXY, never as a verified source: the
        # proxy vouched for it, nobody verified the user's credential here.
        #
        # Reached only when no verified claim was found, so this cannot be used
        # to override a real credential.
        hdr = (body_user_role or "").strip() or _header(request, "X-User-Role")
        user_role, role_source = (hdr, SOURCE_PROXY) if hdr else ("", SOURCE_NONE)
    elif mode in _REFUSING_MODES:
        # STRICT means a self-asserted role is not a role. Falling through to
        # the body or header here is what made `strict` behave identically to
        # `prefer`: both preferred a verified claim and both accepted a typed
        # one when none was present, so there was no mode that actually refused.
        #
        # The caller gets NO role rather than a rejected request: authorization
        # is the caller's decision to make, and a role of "" resolves to no
        # grants everywhere it is consulted. That fails closed without turning
        # a missing credential into a 500 on a path that may not need one.
        user_role, role_source = "", SOURCE_NONE
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
        binding=binding,
        binding_error=binding_error,
        acting_for=(deleg.user_sub if deleg is not None else ""),
        delegation_verified=bool(deleg is not None and deleg.verified),
        delegation_error=(deleg.error if deleg is not None else ""),
    )
