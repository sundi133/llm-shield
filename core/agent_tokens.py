"""Agent token signing and verification (AuthN layer).

An agent token proves WHO is calling. It does NOT grant permission — that
is the job of capability tokens (core/capabilities.py).

Token format
------------
Standard JWT (RFC 7519) with EdDSA (Ed25519) signatures:

    <base64url(header)>.<base64url(payload)>.<base64url(signature)>

The header carries {"alg": "EdDSA", "typ": "JWT", "kid": "<key-id>"}.
Tokens are verifiable by any standards-compliant JWT library.

Legacy two-segment format (base64url(claims).base64url(sig)) is still
accepted during verification for backward compatibility.

Claims:
    iss, aud            issuer/audience binding
    user_sub            who the human is (OIDC sub)
    agent_id            logical agent identity ("billing-bot")
    agent_instance_id   specific running process (unique per boot)
    parent_agent_id     who delegated (None if direct from user)
    tenant_id           tenant scope
    build_hash          exact agent code build (allowlisted)
    model_version       exact LLM weights/version
    session_id          conversation/session
    iat, exp            issued / expires (Unix seconds)
    jti                 unique token id (for revocation by jti)
    kid                 signing key id (for rotation)

Why this design:
  * Asymmetric Ed25519 means tool servers and downstream verifiers can be
    given the public key without ever holding the signing key — defeats
    forging by a compromised tool.
  * Standard JWT format means any OAuth/OIDC library can verify tokens.
  * The token is small enough to put in an HTTP header.
  * ≤15 minute lifetime caps the window of a stolen token.
  * agent_instance_id + jti enable two independent revocation axes
    (kill a misbehaving process; kill a single leaked token).

Key material is loaded from env vars; in production the private key
should live in KMS and only the verifier needs the public key.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from typing import Optional

from cryptography.exceptions import InvalidSignature

from core.identity import IdentityTuple
from core.jwt_utils import JWTError, encode_jwt, decode_jwt, decode_jwt_unverified, is_jwt_format
from core.signers import Signer, SignerError, build_signer

logger = logging.getLogger("votal.agent_tokens")

MAX_TOKEN_TTL_SECONDS = 15 * 60   # hard cap, regardless of caller request
DEFAULT_TOKEN_TTL_SECONDS = 10 * 60

# Default audience for agent tokens. Verifier rejects mismatch.
# Override at deploy time via env to prevent cross-environment token reuse.
DEFAULT_AGENT_AUDIENCE = "shield-agent-tokens"


def _expected_issuer() -> str:
    """The issuer name verify accepts. Tokens minted here carry this value."""
    return os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield"


def _expected_agent_audience() -> str:
    return os.environ.get("SHIELD_AGENT_AUDIENCE", DEFAULT_AGENT_AUDIENCE).strip() or DEFAULT_AGENT_AUDIENCE


def _retired_kids() -> set[str]:
    """Comma-separated list of kids that must never verify again.

    Set SHIELD_RETIRED_KIDS=old1,old2 to block tokens signed with rotated keys.
    """
    raw = os.environ.get("SHIELD_RETIRED_KIDS", "").strip()
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


class TokenError(Exception):
    """Raised when a token fails verification for any reason."""


# ── Key material ─────────────────────────────────────────────────────────

_signer_cache: dict[str, Signer] = {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# AgentTokenSigner is kept for back-compat with any external import sites.
# New code should use the Signer protocol from core.signers.
AgentTokenSigner = Signer


def get_signer(kid: Optional[str] = None) -> Signer:
    """Return the active signer for agent tokens.

    Backend is selected by SHIELD_SIGNER_BACKEND_AGENT (falls back to
    SHIELD_SIGNER_BACKEND). For the local backend, the private key comes
    from SHIELD_AGENT_TOKEN_PRIVATE_KEY (hex, 32 bytes).
    """
    kid = kid or os.environ.get("SHIELD_AGENT_TOKEN_KID", "env")

    if kid in _signer_cache:
        return _signer_cache[kid]

    backend_env = "SHIELD_SIGNER_BACKEND_AGENT" if os.environ.get(
        "SHIELD_SIGNER_BACKEND_AGENT"
    ) else "SHIELD_SIGNER_BACKEND"

    try:
        signer = build_signer(
            kid=kid,
            backend_env=backend_env,
            local_key_env="SHIELD_AGENT_TOKEN_PRIVATE_KEY",
        )
    except SignerError as e:
        logger.error(f"agent_token signer init failed: {e}")
        raise TokenError(f"agent_token signing key misconfigured: {e}") from e

    _signer_cache[kid] = signer
    return signer


def reset_signer_cache_for_tests() -> None:
    """Wipe cached signers; used by test fixtures only."""
    _signer_cache.clear()


# ── Mint / verify ───────────────────────────────────────────────────────


def mint_agent_token(
    *,
    user_sub: str,
    agent_id: str,
    agent_instance_id: str,
    tenant_id: str,
    build_hash: str,
    model_version: str,
    session_id: str,
    parent_agent_id: Optional[str] = None,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    identity_method: str = "agent_token",
    signer: Optional[AgentTokenSigner] = None,
) -> str:
    """Mint a signed agent token as a standard JWT.

    `identity_method` records how the caller proved their identity to the
    mint endpoint. One of: admin_key | spiffe | mtls | oidc_id_token.
    Raises TokenError on misconfiguration.
    """
    if ttl_seconds <= 0 or ttl_seconds > MAX_TOKEN_TTL_SECONDS:
        raise TokenError(
            f"ttl_seconds must be in (0, {MAX_TOKEN_TTL_SECONDS}]; got {ttl_seconds}"
        )
    if not all([user_sub, agent_id, agent_instance_id, tenant_id, build_hash, session_id]):
        raise TokenError("missing required claim")

    signer = signer or get_signer()
    now = int(time.time())

    # RFC 8693 §2.2.1 actor chain. The standard JWT `sub` is the human who
    # authorized the action; `act` carries the agent performing it, and any
    # delegating parent is nested another level deep. The flat fields are
    # retained for backward-compatibility with older verifiers.
    act: dict = {"sub": agent_id, "agent_instance_id": agent_instance_id}
    if parent_agent_id:
        act["act"] = {"sub": parent_agent_id}

    claims = {
        "iss": _expected_issuer(),
        "aud": _expected_agent_audience(),
        "sub": user_sub,
        "act": act,
        "user_sub": user_sub,
        "agent_id": agent_id,
        "agent_instance_id": agent_instance_id,
        "parent_agent_id": parent_agent_id,
        "tenant_id": tenant_id,
        "build_hash": build_hash,
        "model_version": model_version,
        "session_id": session_id,
        "identity_method": identity_method,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "kid": signer.kid,
    }
    try:
        return encode_jwt(claims, signer)
    except JWTError as e:
        raise TokenError(f"failed to mint JWT: {e}") from e


def _allowed_builds() -> Optional[set[str]]:
    """Optional allowlist of build_hash values.

    Set SHIELD_AGENT_ALLOWED_BUILDS to a comma-separated list to enforce.
    If unset, any build_hash is accepted (useful for dev/tests).
    """
    raw = os.environ.get("SHIELD_AGENT_ALLOWED_BUILDS", "").strip()
    if not raw:
        return None
    return {b.strip() for b in raw.split(",") if b.strip()}


def verify_agent_token(token: str) -> IdentityTuple:
    """Verify a token and return the IdentityTuple it carries.

    Accepts both standard JWT (3-segment) and legacy (2-segment) formats.
    Checks: signature, exp, required claims, build_hash allowlist,
    instance/jti revocation. Raises TokenError on any failure.
    """
    if not token or "." not in token:
        raise TokenError("malformed token")

    # Extract kid from unverified claims first for retired-kid check
    try:
        unverified = decode_jwt_unverified(token)
    except Exception as e:
        raise TokenError(f"undecodable token: {e}") from e

    kid = unverified.get("kid", "env")
    # Reject retired kids before doing any work with them (H1/M2).
    if kid in _retired_kids():
        raise TokenError(f"kid retired: {kid}")

    signer = get_signer(kid)

    if is_jwt_format(token):
        # Standard JWT (3-segment) verification
        try:
            claims = decode_jwt(token, signer)
        except JWTError as e:
            raise TokenError(str(e)) from e
    else:
        # Legacy 2-segment format: base64url(claims).base64url(sig)
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload = _b64url_decode(payload_b64)
            sig = _b64url_decode(sig_b64)
            claims = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise TokenError(f"undecodable token: {e}") from e

        try:
            signer.verify(payload, sig)
        except InvalidSignature as e:
            raise TokenError("invalid signature") from e

        # Check expiry for legacy format
        now = int(time.time())
        if "exp" in claims and claims["exp"] < now - 5:
            raise TokenError("token expired")

    # Required claims
    required = (
        "iss", "aud", "user_sub", "agent_id", "agent_instance_id", "tenant_id",
        "build_hash", "model_version", "session_id", "iat", "exp", "jti",
    )
    for k in required:
        if k not in claims:
            raise TokenError(f"missing claim: {k}")

    # Issuer + audience binding (H1). Prevents tokens from one Shield
    # deployment validating in another and tokens minted for the agent-token
    # signer from being mistaken for caps (and vice versa).
    if claims["iss"] != _expected_issuer():
        raise TokenError(f"issuer mismatch: {claims['iss']!r}")
    if claims["aud"] != _expected_agent_audience():
        raise TokenError(f"audience mismatch: {claims['aud']!r}")

    # Future-issued check
    now = int(time.time())
    if claims["iat"] > now + 30:
        raise TokenError("token issued in the future")

    # Build allowlist
    allowed = _allowed_builds()
    if allowed is not None and claims["build_hash"] not in allowed:
        raise TokenError(f"build_hash not allowed: {claims['build_hash']}")

    # Revocation
    from storage.revocation import (
        is_instance_revoked,
        is_jti_revoked,
        is_user_revoked,
    )
    if is_instance_revoked(claims["agent_instance_id"]):
        raise TokenError("agent_instance_id revoked")
    if is_jti_revoked(claims["jti"]):
        raise TokenError("token revoked")
    if is_user_revoked(claims["user_sub"]):
        raise TokenError("user revoked")

    return IdentityTuple(
        user_sub=claims["user_sub"],
        agent_id=claims["agent_id"],
        agent_instance_id=claims["agent_instance_id"],
        parent_agent_id=claims.get("parent_agent_id"),
        tenant_id=claims["tenant_id"],
        build_hash=claims["build_hash"],
        model_version=claims["model_version"],
        session_id=claims["session_id"],
        trust_level="high",  # signed token implies high-trust identity
        identity_method=claims.get("identity_method", "agent_token"),
    )


def decode_claims_unverified(token: str) -> dict:
    """Decode claims without verifying signature. For diagnostics only.

    Handles both JWT (3-segment) and legacy (2-segment) formats.
    """
    return decode_jwt_unverified(token)
