"""Approval grants (non-fakeable Human-In-The-Loop).

An approval grant is a signed, single-use, short-lived token proving that an
**authenticated human** (or a quorum) approved ONE specific action. It is the
AuthZ analog of a capability, but the authority is a *person*, not a policy:

    request created  ->  human(s) approve (authenticated)  ->  SIGNED GRANT
        ->  presented at cap/mint  ->  verified + nonce burned  ->  action runs

Why signed (not a Redis "approved" flag): a flag is forgeable by anyone with
Redis/backup access, and the approver is otherwise a caller-asserted string.
A grant binds the exact action (tool, resource, params_hash, agent instance,
session) and the verified approver identities into an Ed25519 signature that the
guard path checks in microseconds. See docs/spec-hitl-breakglass.md.

Break-glass grants use a distinct audience and carry ``breakglass:true`` plus the
authorizing admin and a mandatory reason — a loud, time-boxed emergency override.

Mirrors core/capabilities.py (own signer, own nonce namespace, own audience) so a
leaked cap or agent-token signer cannot forge an approval and vice-versa.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

from core.jwt_utils import JWTError, decode_jwt, decode_jwt_unverified, encode_jwt
from core.nonce_store import NonceStoreUnavailable, burn_nonce_if_unused
from core.signers import Signer, SignerError, build_signer

APPROVAL_AUDIENCE = "shield-approvals"
BREAKGLASS_AUDIENCE = "shield-breakglass"

# Grant lifetimes (short: a grant is consumed right after issuance).
DEFAULT_GRANT_TTL_SECONDS = int(os.getenv("SHIELD_APPROVAL_GRANT_TTL", "300"))
DEFAULT_BREAKGLASS_TTL_SECONDS = int(os.getenv("SHIELD_BREAKGLASS_TTL", "900"))
MAX_GRANT_TTL_SECONDS = 3600


class ApprovalError(Exception):
    """Raised when an approval grant fails to mint or verify."""


def _issuer() -> str:
    return os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield"


def _approval_audience() -> str:
    return os.environ.get("SHIELD_APPROVAL_AUDIENCE", APPROVAL_AUDIENCE).strip() or APPROVAL_AUDIENCE


# ── params binding ───────────────────────────────────────────────────


def params_hash(tool_params: Optional[dict]) -> str:
    """Canonical sha256 of tool params — binds a grant to the exact call.

    Must be computed identically when the approval request is created and when
    the grant is verified at cap/mint, so a changed argument invalidates the grant.
    """
    canonical = json.dumps(
        tool_params or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── signer (separate from agent/cap signers) ─────────────────────────

_signer_cache: dict[str, Signer] = {}


def get_approval_signer(kid: Optional[str] = None) -> Signer:
    kid = kid or os.environ.get("SHIELD_APPROVAL_TOKEN_KID", "approval-env")
    if kid in _signer_cache:
        return _signer_cache[kid]
    backend_env = (
        "SHIELD_SIGNER_BACKEND_APPROVAL"
        if os.environ.get("SHIELD_SIGNER_BACKEND_APPROVAL")
        else "SHIELD_SIGNER_BACKEND"
    )
    try:
        signer = build_signer(
            kid=kid,
            backend_env=backend_env,
            local_key_env="SHIELD_APPROVAL_TOKEN_PRIVATE_KEY",
        )
    except SignerError as e:
        raise ApprovalError(f"approval signing key misconfigured: {e}") from e
    _signer_cache[kid] = signer
    return signer


def reset_signer_cache_for_tests() -> None:
    _signer_cache.clear()


# ── nonce store (one-shot) ───────────────────────────────────────────

_NONCE_PREFIX = "shield:approval:nonce:"


def _burn_nonce_if_unused(nonce: str, ttl: int) -> bool:
    """Atomically claim a nonce. True if first-use, False if replayed.

    Raises NonceStoreUnavailable if Redis is configured but unreachable. An
    approval grant is a human's "yes"; letting one be reused because the store
    blinked is the outcome least worth risking.
    """
    return burn_nonce_if_unused(_NONCE_PREFIX + nonce, ttl)


def clear_nonce_store_for_tests() -> None:
    from storage.tenant_store import _fallback_store

    for k in list(_fallback_store.keys()):
        if k.startswith(_NONCE_PREFIX):
            _fallback_store.pop(k, None)


# ── claims ───────────────────────────────────────────────────────────


@dataclass
class GrantClaims:
    tenant_id: str
    agent_id: str
    agent_instance_id: str
    session_id: str
    tool: str
    resource: str
    params_hash: str
    approvers: List[dict]
    request_id: str
    grant_id: str
    nonce: str
    iat: int
    exp: int
    kid: str
    breakglass: bool = False
    reason: str = ""
    authorized_by: str = ""


# ── mint ─────────────────────────────────────────────────────────────


def mint_grant(
    *,
    tenant_id: str,
    agent_id: str,
    agent_instance_id: str,
    session_id: str,
    tool: str,
    resource: str,
    params_hash: str,
    approvers: List[dict],
    request_id: str,
    ttl_seconds: Optional[int] = None,
    breakglass: bool = False,
    reason: str = "",
    authorized_by: str = "",
    signer: Optional[Signer] = None,
) -> str:
    """Freeze an approval decision into a signed, single-use grant token."""
    if not tool or not resource:
        raise ApprovalError("tool and resource are required")
    if breakglass and not (reason and authorized_by):
        raise ApprovalError("break-glass grants require reason and authorized_by")
    ttl = ttl_seconds or (DEFAULT_BREAKGLASS_TTL_SECONDS if breakglass else DEFAULT_GRANT_TTL_SECONDS)
    if ttl <= 0 or ttl > MAX_GRANT_TTL_SECONDS:
        raise ApprovalError(f"ttl_seconds must be in (0, {MAX_GRANT_TTL_SECONDS}]; got {ttl}")

    signer = signer or get_approval_signer()
    now = int(time.time())
    claims = {
        "iss": _issuer(),
        "aud": BREAKGLASS_AUDIENCE if breakglass else _approval_audience(),
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "agent_instance_id": agent_instance_id,
        "session_id": session_id,
        "tool": tool,
        "resource": resource,
        "params_hash": params_hash,
        "approvers": list(approvers or []),
        "request_id": request_id,
        "grant_id": uuid.uuid4().hex,
        "nonce": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl,
        "breakglass": breakglass,
        "reason": reason,
        "authorized_by": authorized_by,
        "kid": signer.kid,
    }
    try:
        return encode_jwt(claims, signer)
    except JWTError as e:
        raise ApprovalError(f"failed to mint approval grant: {e}") from e


# ── verify ───────────────────────────────────────────────────────────


def verify_grant(
    token: str,
    *,
    expected_tool: str,
    expected_resource: Optional[str] = None,
    expected_params_hash: Optional[str] = None,
    expected_instance: Optional[str] = None,
    expected_session: Optional[str] = None,
    allow_breakglass: bool = True,
    burn_nonce: bool = True,
) -> GrantClaims:
    """Verify an approval (or break-glass) grant and bind it to this action.

    Checks signature, issuer/audience, expiry, exact tool/resource/params_hash,
    optional instance/session binding, instance revocation, and burns the nonce.
    """
    if not token or "." not in token:
        raise ApprovalError("malformed approval grant")
    try:
        unverified = decode_jwt_unverified(token)
    except Exception as e:
        raise ApprovalError(f"undecodable approval grant: {e}") from e

    kid = unverified.get("kid", "approval-env")
    signer = get_approval_signer(kid)
    try:
        claims = decode_jwt(token, signer, clock_skew_seconds=2)
    except JWTError as e:
        raise ApprovalError(str(e)) from e

    required = (
        "iss", "aud", "tenant_id", "agent_id", "agent_instance_id", "session_id",
        "tool", "resource", "params_hash", "request_id", "grant_id", "nonce",
        "iat", "exp",
    )
    for k in required:
        if k not in claims:
            raise ApprovalError(f"missing claim: {k}")

    if claims["iss"] != _issuer():
        raise ApprovalError(f"approval issuer mismatch: {claims['iss']!r}")
    is_breakglass = bool(claims.get("breakglass"))
    expected_aud = BREAKGLASS_AUDIENCE if is_breakglass else _approval_audience()
    if claims["aud"] != expected_aud:
        raise ApprovalError(f"approval audience mismatch: {claims['aud']!r}")
    if is_breakglass and not allow_breakglass:
        raise ApprovalError("break-glass grant not accepted here")

    if claims["tool"] != expected_tool:
        raise ApprovalError(
            f"approval tool mismatch: token={claims['tool']!r} expected={expected_tool!r}"
        )
    if expected_resource is not None and claims["resource"] != expected_resource:
        raise ApprovalError("approval resource mismatch")
    if expected_params_hash is not None and claims["params_hash"] != expected_params_hash:
        raise ApprovalError("approval params mismatch (arguments changed since approval)")
    if expected_instance is not None and claims["agent_instance_id"] != expected_instance:
        raise ApprovalError("approval instance mismatch")
    if expected_session is not None and claims["session_id"] != expected_session:
        raise ApprovalError("approval session mismatch")

    from storage.revocation import is_instance_revoked, is_jti_revoked

    if is_jti_revoked(claims["grant_id"]):
        raise ApprovalError("approval grant revoked")
    if is_instance_revoked(claims["agent_instance_id"]):
        raise ApprovalError("approval revoked (agent instance revoked)")

    if burn_nonce:
        now = int(time.time())
        nonce_ttl = max(1, claims["exp"] - now + 5)
        try:
            first_use = _burn_nonce_if_unused(claims["nonce"], nonce_ttl)
        except NonceStoreUnavailable as e:
            raise ApprovalError(f"approval verification unavailable: {e}") from e
        if not first_use:
            raise ApprovalError("approval replay detected (nonce already used)")

    return GrantClaims(
        tenant_id=claims["tenant_id"],
        agent_id=claims["agent_id"],
        agent_instance_id=claims["agent_instance_id"],
        session_id=claims["session_id"],
        tool=claims["tool"],
        resource=claims["resource"],
        params_hash=claims["params_hash"],
        approvers=list(claims.get("approvers", [])),
        request_id=claims["request_id"],
        grant_id=claims["grant_id"],
        nonce=claims["nonce"],
        iat=claims["iat"],
        exp=claims["exp"],
        kid=kid,
        breakglass=is_breakglass,
        reason=claims.get("reason", ""),
        authorized_by=claims.get("authorized_by", ""),
    )
