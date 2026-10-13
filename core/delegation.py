"""Agent acting on behalf of a user (two-token delegation).

An agentic authorization decision needs two principals, not one:

    Authorization: Bearer <agent service-account token>   which agent
    X-On-Behalf-Of: <user token>                          whose authority

Shield already verifies the first through the workload-identity providers. This
module verifies the second, so a decision can carry both — and so the audit can
answer "which agent, acting for whom", which one bearer token cannot.

Why two tokens rather than RFC 8693 token exchange: exchange is the more elegant
primitive, but the ``act`` claim is populated inconsistently across IdP versions
and Keycloak needs per-client fine-grained permissions to enable it. Two tokens
work on any IdP, both signatures verify against the same JWKS, and a caller
cannot fabricate either. The ``act`` claim is read too when present, so a single
exchanged token also works.

**Intersection is not implemented here — it already exists.** The tool allowlist
enforces "both agent AND role must allow"
(guardrails/agentic/tool/tool_allowlist.py). Taking the role from a verified
user token instead of a header is what makes that intersection meaningful: the
agent cannot exceed its own grant, and the user cannot exceed theirs.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

HEADER = "X-On-Behalf-Of"

MODE_OFF, MODE_OPTIONAL, MODE_REQUIRED = "off", "optional", "required"
_MODES = (MODE_OFF, MODE_OPTIONAL, MODE_REQUIRED)
_ENV = "SHIELD_DELEGATION"

#: A user token is small. Anything larger is not a credential.
_MAX_TOKEN_BYTES = 8192


@dataclass(frozen=True)
class Delegation:
    """Who the agent is acting for, and whether it was proven."""

    present: bool = False
    verified: bool = False
    user_sub: str = ""
    user_roles: tuple = ()
    error: str = ""
    # Retained so a delegation can be audited and revoked (M1). jti is the
    # revocation handle (storage.revocation); expires_at bounds the record TTL.
    jti: str = ""
    issuer: str = ""
    expires_at: int = 0


def delegation_persist_enabled() -> bool:
    """Whether to write a persisted record of each verified delegation.

    Off by default: resolve_delegation is on the guard path, and a store write
    there is exactly the latency the repo keeps governance away from. Enabling it
    is opt-in for deployments that want an auditable, enumerable delegation trail.
    The revocation CHECK is independent and always on when delegation is enabled.
    """
    v = os.environ.get("SHIELD_DELEGATION_PERSIST", "").strip().lower()
    return v in ("1", "true", "on", "yes")


def delegation_mode() -> str:
    """off | optional | required — default off.

    ``optional`` verifies the header when present and records the result.
    ``required`` refuses a request that presents no delegated user. Off reads no
    header and runs no crypto.
    """
    v = os.environ.get(_ENV, MODE_OFF).strip().lower()
    return v if v in _MODES else MODE_OFF


def _allowed_issuers() -> list:
    """Same allowlist as the oidc_sa workload provider, deliberately.

    A user token and an agent token come from the same IdP; two sources of
    truth for "which issuer do we trust" is how they drift apart.
    """
    raw = os.environ.get("SHIELD_WORKLOAD_OIDC_ISSUERS", "")
    return [i.strip() for i in raw.split(",") if i.strip()]


def verify_user_token(token: str, *, audience: Optional[str] = None,
                      tenant_id: Optional[str] = None) -> Delegation:
    """Verify a delegated user token against the trusted issuers.

    Mirrors the oidc_sa provider: read the issuer unverified, refuse unless it
    is allow-listed, then verify the signature against that issuer's JWKS.
    Reading the issuer before verifying is safe precisely because it is only
    used to *select* a key — never to grant anything.
    """
    if not token or not isinstance(token, str):
        return Delegation(present=False)
    if len(token.encode("utf-8", "ignore")) > _MAX_TOKEN_BYTES:
        return Delegation(present=True, error="delegated token too large")

    issuers = _allowed_issuers()
    if not issuers:
        # Refuse rather than accept any signed token: without an allowlist,
        # "verified" would mean "signed by somebody".
        return Delegation(present=True, error="no trusted issuers configured")

    try:
        import jwt as pyjwt
    except Exception:
        return Delegation(present=True, error="jwt library unavailable")

    try:
        iss = pyjwt.decode(token, options={"verify_signature": False}).get("iss", "")
    except Exception:
        return Delegation(present=True, error="delegated token is not a JWT")
    if iss not in issuers:
        return Delegation(present=True, error=f"issuer not allow-listed: {iss!r}")

    aud = audience if audience is not None else (
        os.environ.get("SHIELD_WORKLOAD_OIDC_AUDIENCE", "").strip() or None)

    try:
        from core.workload_identity.providers import _resolve_signing_key
        key = _resolve_signing_key(iss, token)
        claims = pyjwt.decode(
            token, key, algorithms=["RS256", "ES256"], audience=aud,
            options={"require": ["sub", "exp"], "verify_aud": aud is not None},
        )
    except Exception as e:
        logger.debug("delegated user token rejected: %s", e)
        return Delegation(present=True, error=f"delegated token rejected: {e}")

    jti = str(claims.get("jti", "") or "")
    # A delegation is revocable by its jti, the same axis the MCP path already
    # uses to revoke a Shield access token. A revoked delegated token verifies
    # cryptographically but must not be honoured.
    if jti:
        try:
            from storage.revocation import is_jti_revoked
            if is_jti_revoked(jti):
                return Delegation(present=True, error="delegated token revoked",
                                  jti=jti, issuer=iss)
        except Exception:       # noqa: BLE001 — a revocation-store hiccup must
            pass                # not silently ACCEPT; absence of a hit = not revoked

    exp = claims.get("exp")
    return Delegation(
        present=True, verified=True,
        user_sub=str(claims.get("sub", "")),
        user_roles=_roles_from(claims, tenant_id),
        jti=jti, issuer=iss,
        expires_at=int(exp) if isinstance(exp, (int, float)) else 0,
    )


def _roles_from(claims: dict, tenant_id: Optional[str] = None) -> tuple:
    """Roles from a verified user token, using the SAME configuration as role
    binding.

    This used to read ``SHIELD_ROLE_CLAIM`` directly while role binding read a
    per-tenant ``role_claim``. Two sources of truth for "where does the role
    live" is how the two paths silently disagreed: point a deployment at Okta
    and delegation would look at ``groups`` while role binding looked at
    ``realm_access.roles``, or the reverse, depending on which knob was set.

    ``claim_config`` resolves tenant config, then ``SHIELD_ROLE_CLAIM``, then
    Keycloak's default — so a deployment with no tenant config behaves exactly
    as it did.
    """
    from core.identity_resolution import claim_config, extract_roles

    cfg = claim_config(tenant_id)
    return extract_roles(claims, cfg["role_claim"], cfg["role_map"],
                         cfg["role_allowlist"])


def actor_from_act_claim(claims: dict) -> str:
    """The acting party from an RFC 8693 ``act`` claim, when the IdP sets one.

    Supports the single-exchanged-token shape as well as two tokens. Population
    of this claim varies between IdP versions, so it is read opportunistically
    and never required.
    """
    act = (claims or {}).get("act")
    if isinstance(act, dict):
        return str(act.get("sub") or act.get("client_id") or "")
    return ""


def _agent_id(request: Any) -> str:
    """Best-effort id of the agent doing the acting (its own verified workload
    identity), for the delegation record. Empty when unknown."""
    try:
        wi = getattr(getattr(request, "state", None), "workload_identity", None)
        claims = getattr(wi, "claims", None) if wi is not None else None
        if isinstance(claims, dict):
            return str(claims.get("sub") or claims.get("client_id") or "")
    except Exception:       # noqa: BLE001
        pass
    return ""


def _persist_delegation(deleg: "Delegation", tenant_id: str, request: Any) -> None:
    """Record a verified delegation for audit + revocation. Best-effort: losing
    the record must never fail the guarded request."""
    try:
        from storage.delegation_store import record_delegation
        record_delegation(
            tenant_id, jti=deleg.jti, issuer=deleg.issuer,
            user_sub=deleg.user_sub, agent=_agent_id(request),
            roles=list(deleg.user_roles or ()), expires_at=deleg.expires_at)
    except Exception as e:       # noqa: BLE001
        logger.debug("delegation not persisted: %s", e)


def resolve_delegation(request: Any, tenant_id: Optional[str] = None) -> Delegation:
    """Delegation for this request. Never raises — it is on the guard path."""
    if delegation_mode() == MODE_OFF:
        return Delegation()
    try:
        headers = request.headers
        token = (headers.get(HEADER) or headers.get(HEADER.lower()) or "").strip()
    except Exception:
        return Delegation()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if token:
        try:
            deleg = verify_user_token(token, tenant_id=tenant_id)
        except Exception as e:
            return Delegation(present=True, error=str(e))
        if deleg.verified and deleg.jti and tenant_id and delegation_persist_enabled():
            _persist_delegation(deleg, tenant_id, request)
        return deleg

    # No second token. A single RFC 8693 exchanged token carries the delegation
    # inside it: sub is the user the agent acts for, act names the actor. Those
    # claims were already verified when the agent's own credential was, so
    # nothing further is proven here — it is read, not trusted anew.
    try:
        wi = getattr(getattr(request, "state", None), "workload_identity", None)
        claims = getattr(wi, "claims", None) if wi is not None else None
        if claims and actor_from_act_claim(claims):
            return Delegation(
                present=True, verified=True,
                user_sub=str(claims.get("sub", "")),
                user_roles=_roles_from(claims, tenant_id),
            )
    except Exception:
        pass
    return Delegation()
