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


def verify_user_token(token: str, *, audience: Optional[str] = None) -> Delegation:
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

    return Delegation(
        present=True, verified=True,
        user_sub=str(claims.get("sub", "")),
        user_roles=_roles_from(claims),
    )


def _roles_from(claims: dict) -> tuple:
    from core.identity_resolution import extract_roles

    path = os.environ.get("SHIELD_ROLE_CLAIM", "realm_access.roles").strip()
    return extract_roles(claims, path)


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


def resolve_delegation(request: Any) -> Delegation:
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
    if not token:
        return Delegation()
    try:
        return verify_user_token(token)
    except Exception as e:
        return Delegation(present=True, error=str(e))
