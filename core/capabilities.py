"""Capability tokens (AuthZ layer).

A capability token is a signed, single-use, short-lived grant for ONE
specific action. The gateway mints it AFTER the guardrail pipeline
approves an action; the tool/MCP server verifies it before executing.

Why a separate signer from agent tokens
---------------------------------------
Tool servers only need the cap public key — they never need the agent-
token public key. Separating the two means a compromised tool cannot
forge an identity token, only the (already narrowly-scoped) caps it can
already see.

Why nonces
----------
A leaked cap with 60 seconds of validity is bad enough; without a nonce
it could be replayed N times in those 60 seconds. The verifier burns the
nonce on first use (Redis or fallback). Replays fail.

Claims
------
    user_sub, agent_id, agent_instance_id  — bound identity from AuthN
    tool                                   — exact tool name
    resource                               — exact target (e.g. user/42/inbox)
    scope                                  — list of constraints intersection
    clearance_max                          — data clearance ceiling
    parent_cap_id                          — if minted for a delegated call
    nonce, iat, exp, kid, cap_id
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

from cryptography.exceptions import InvalidSignature

from core.identity import IdentityTuple
from core.signers import Signer, SignerError, build_signer

logger = logging.getLogger("votal.capabilities")

CAP_MAX_TTL_SECONDS = 60
CAP_DEFAULT_TTL_SECONDS = 30


class CapabilityError(Exception):
    """Raised when a capability token fails to mint or verify."""


# Default audience for capability tokens. Distinct from the agent-token
# audience so a leaked agent-token signer cannot be used to forge caps
# even if the cap signer also (mis)trusts that kid.
DEFAULT_CAP_AUDIENCE = "shield-capabilities"


def _expected_cap_issuer() -> str:
    return os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield"


def _expected_cap_audience() -> str:
    return os.environ.get("SHIELD_CAP_AUDIENCE", DEFAULT_CAP_AUDIENCE).strip() or DEFAULT_CAP_AUDIENCE


def _cap_retired_kids() -> set[str]:
    raw = os.environ.get("SHIELD_RETIRED_KIDS", "").strip()
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


# ── Signer (separate from agent_tokens signer) ───────────────────────────

_cap_signer_cache: dict[str, Signer] = {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# CapSigner is kept for back-compat with any external import sites.
# New code should use the Signer protocol from core.signers.
CapSigner = Signer


def get_cap_signer(kid: Optional[str] = None) -> Signer:
    """Return the active signer for capability tokens.

    Backend is selected by SHIELD_SIGNER_BACKEND_CAP (falls back to
    SHIELD_SIGNER_BACKEND). For the local backend, the private key comes
    from SHIELD_CAP_TOKEN_PRIVATE_KEY (hex, 32 bytes).
    """
    kid = kid or os.environ.get("SHIELD_CAP_TOKEN_KID", "cap-env")
    if kid in _cap_signer_cache:
        return _cap_signer_cache[kid]

    backend_env = "SHIELD_SIGNER_BACKEND_CAP" if os.environ.get(
        "SHIELD_SIGNER_BACKEND_CAP"
    ) else "SHIELD_SIGNER_BACKEND"

    try:
        signer = build_signer(
            kid=kid,
            backend_env=backend_env,
            local_key_env="SHIELD_CAP_TOKEN_PRIVATE_KEY",
        )
    except SignerError as e:
        logger.error(f"cap signer init failed: {e}")
        raise CapabilityError(f"cap signing key misconfigured: {e}") from e

    _cap_signer_cache[kid] = signer
    return signer


def reset_cap_signer_cache_for_tests() -> None:
    _cap_signer_cache.clear()


# ── Nonce store (one-shot) ───────────────────────────────────────────────

_NONCE_KEY_PREFIX = "shield:cap:nonce:"


def _burn_nonce_if_unused(nonce: str, ttl: int) -> bool:
    """Atomically claim a nonce. Returns True if first-use, False if replayed.

    Uses Redis SETNX (via `set(nx=True)`) when available, falls back to
    in-process dict for tests/dev.
    """
    from storage.tenant_store import _get_redis, _fallback_store

    key = _NONCE_KEY_PREFIX + nonce
    r = _get_redis()
    if r:
        try:
            # nx=True → only set if key doesn't exist (atomic claim)
            ok = r.set(key, "1", ex=ttl, nx=True)
            return bool(ok)
        except Exception:
            pass
    if key in _fallback_store:
        return False
    _fallback_store[key] = str(int(time.time()) + ttl)
    return True


def clear_nonce_store_for_tests() -> None:
    from storage.tenant_store import _fallback_store
    for k in list(_fallback_store.keys()):
        if k.startswith(_NONCE_KEY_PREFIX):
            _fallback_store.pop(k, None)


# ── Claims dataclass ─────────────────────────────────────────────────────


@dataclass
class CapClaims:
    user_sub: str
    agent_id: str
    agent_instance_id: str
    tool: str
    resource: str
    scope: List[str]
    clearance_max: str
    nonce: str
    iat: int
    exp: int
    cap_id: str
    kid: str
    parent_cap_id: Optional[str] = None
    tenant_id: str = ""


# ── Mint / verify ────────────────────────────────────────────────────────


def mint_cap(
    *,
    identity: IdentityTuple,
    tool: str,
    resource: str,
    scope: Optional[List[str]] = None,
    clearance_max: str = "public",
    ttl_seconds: int = CAP_DEFAULT_TTL_SECONDS,
    parent_cap_id: Optional[str] = None,
    signer: Optional[CapSigner] = None,
) -> str:
    """Mint a capability token.

    The caller MUST have already run the guardrail pipeline and confirmed
    the action is allowed. This function does not re-check policy — it
    freezes the decision into a verifiable artifact.
    """
    if ttl_seconds <= 0 or ttl_seconds > CAP_MAX_TTL_SECONDS:
        raise CapabilityError(
            f"ttl_seconds must be in (0, {CAP_MAX_TTL_SECONDS}]; got {ttl_seconds}"
        )
    if not tool or not resource:
        raise CapabilityError("tool and resource are required")
    if clearance_max not in ("public", "internal", "confidential", "restricted"):
        raise CapabilityError(f"invalid clearance_max: {clearance_max}")

    signer = signer or get_cap_signer()
    now = int(time.time())
    cap_id = uuid.uuid4().hex
    claims = {
        "iss": _expected_cap_issuer(),
        "aud": _expected_cap_audience(),
        "user_sub": identity.user_sub,
        "agent_id": identity.agent_id,
        "agent_instance_id": identity.agent_instance_id,
        "tenant_id": identity.tenant_id,
        "tool": tool,
        "resource": resource,
        "scope": list(scope or []),
        "clearance_max": clearance_max,
        "nonce": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
        "cap_id": cap_id,
        "parent_cap_id": parent_cap_id,
        "kid": signer.kid,
    }
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = signer.sign(payload)
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def verify_cap(
    token: str,
    *,
    expected_tool: str,
    expected_resource: Optional[str] = None,
    burn_nonce: bool = True,
) -> CapClaims:
    """Verify a capability token.

    Checks: signature, exp, tool match, optional resource match,
    cap_id revocation, and burns the nonce (single-use semantics).
    """
    if not token or "." not in token:
        raise CapabilityError("malformed cap token")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
        claims = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise CapabilityError(f"undecodable cap token: {e}") from e

    kid = claims.get("kid", "cap-env")
    # Reject retired cap-signing kids (H1/M2).
    if kid in _cap_retired_kids():
        raise CapabilityError(f"cap kid retired: {kid}")
    signer = get_cap_signer(kid)
    try:
        signer.verify(payload, sig)
    except InvalidSignature as e:
        raise CapabilityError("invalid cap signature") from e

    required = (
        "iss", "aud", "user_sub", "agent_id", "agent_instance_id", "tool", "resource",
        "scope", "clearance_max", "nonce", "iat", "exp", "cap_id",
    )
    for k in required:
        if k not in claims:
            raise CapabilityError(f"missing claim: {k}")

    # Issuer + audience binding (H1). Cap aud must NOT equal the agent-token
    # aud — that prevents a leaked agent-token from being verified as a cap.
    if claims["iss"] != _expected_cap_issuer():
        raise CapabilityError(f"cap issuer mismatch: {claims['iss']!r}")
    if claims["aud"] != _expected_cap_audience():
        raise CapabilityError(f"cap audience mismatch: {claims['aud']!r}")

    now = int(time.time())
    if claims["exp"] < now - 2:
        raise CapabilityError("cap expired")

    if claims["tool"] != expected_tool:
        raise CapabilityError(
            f"cap tool mismatch: token={claims['tool']!r} expected={expected_tool!r}"
        )
    if expected_resource is not None and claims["resource"] != expected_resource:
        raise CapabilityError(
            f"cap resource mismatch: token={claims['resource']!r} expected={expected_resource!r}"
        )

    # cap_id revocation reuses the jti revocation list
    from storage.revocation import is_jti_revoked
    if is_jti_revoked(claims["cap_id"]):
        raise CapabilityError("cap revoked")

    # Burn nonce (one-shot)
    if burn_nonce:
        # nonce TTL = remaining cap lifetime + 5s grace
        nonce_ttl = max(1, claims["exp"] - now + 5)
        if not _burn_nonce_if_unused(claims["nonce"], nonce_ttl):
            raise CapabilityError("cap replay detected (nonce already used)")

    return CapClaims(
        user_sub=claims["user_sub"],
        agent_id=claims["agent_id"],
        agent_instance_id=claims["agent_instance_id"],
        tool=claims["tool"],
        resource=claims["resource"],
        scope=list(claims["scope"]),
        clearance_max=claims["clearance_max"],
        nonce=claims["nonce"],
        iat=claims["iat"],
        exp=claims["exp"],
        cap_id=claims["cap_id"],
        kid=kid,
        parent_cap_id=claims.get("parent_cap_id"),
        tenant_id=claims.get("tenant_id", ""),
    )
