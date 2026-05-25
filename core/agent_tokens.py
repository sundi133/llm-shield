"""Agent token signing and verification (AuthN layer).

An agent token proves WHO is calling. It does NOT grant permission — that
is the job of capability tokens (core/capabilities.py).

Token format
------------
A compact, self-contained, Ed25519-signed envelope:

    <base64url(claims_json)>.<base64url(signature)>

Claims:
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
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.identity import IdentityTuple

logger = logging.getLogger("votal.agent_tokens")

MAX_TOKEN_TTL_SECONDS = 15 * 60   # hard cap, regardless of caller request
DEFAULT_TOKEN_TTL_SECONDS = 10 * 60


class TokenError(Exception):
    """Raised when a token fails verification for any reason."""


# ── Key material ─────────────────────────────────────────────────────────

_signer_cache: dict[str, "AgentTokenSigner"] = {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


@dataclass
class AgentTokenSigner:
    """Pluggable signer. v1 is Ed25519 from env; v2 can be KMS-backed."""

    kid: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> None:
        self.public_key.verify(signature, payload)


def _generate_signer(kid: str = "dev") -> AgentTokenSigner:
    sk = Ed25519PrivateKey.generate()
    return AgentTokenSigner(kid=kid, private_key=sk, public_key=sk.public_key())


def get_signer(kid: Optional[str] = None) -> AgentTokenSigner:
    """Return the active signer.

    Resolution order:
      1. SHIELD_AGENT_TOKEN_PRIVATE_KEY env (hex, 32 bytes) → kid=env_kid (default 'env')
      2. cached generated key for `kid` (dev/test only)
    """
    kid = kid or os.environ.get("SHIELD_AGENT_TOKEN_KID", "env")

    if kid in _signer_cache:
        return _signer_cache[kid]

    env_hex = os.environ.get("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "").strip()
    if env_hex:
        try:
            sk_bytes = bytes.fromhex(env_hex)
            sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
            signer = AgentTokenSigner(kid=kid, private_key=sk, public_key=sk.public_key())
            _signer_cache[kid] = signer
            return signer
        except Exception as e:
            logger.error(f"Invalid SHIELD_AGENT_TOKEN_PRIVATE_KEY: {e}")
            raise TokenError("agent_token signing key misconfigured") from e

    # No env key — generate an ephemeral one (dev/test only).
    # Persist in cache so verify works within the process.
    signer = _generate_signer(kid)
    _signer_cache[kid] = signer
    logger.warning(
        f"agent_tokens: no SHIELD_AGENT_TOKEN_PRIVATE_KEY set; using ephemeral key (kid={kid}). "
        "DO NOT use this in production."
    )
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
    signer: Optional[AgentTokenSigner] = None,
) -> str:
    """Mint a signed agent token. Raises TokenError on misconfiguration."""
    if ttl_seconds <= 0 or ttl_seconds > MAX_TOKEN_TTL_SECONDS:
        raise TokenError(
            f"ttl_seconds must be in (0, {MAX_TOKEN_TTL_SECONDS}]; got {ttl_seconds}"
        )
    if not all([user_sub, agent_id, agent_instance_id, tenant_id, build_hash, session_id]):
        raise TokenError("missing required claim")

    signer = signer or get_signer()
    now = int(time.time())
    claims = {
        "user_sub": user_sub,
        "agent_id": agent_id,
        "agent_instance_id": agent_instance_id,
        "parent_agent_id": parent_agent_id,
        "tenant_id": tenant_id,
        "build_hash": build_hash,
        "model_version": model_version,
        "session_id": session_id,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "kid": signer.kid,
    }
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = signer.sign(payload)
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


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

    Checks: signature, exp, required claims, build_hash allowlist,
    instance/jti revocation. Raises TokenError on any failure.
    """
    if not token or "." not in token:
        raise TokenError("malformed token")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
        claims = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise TokenError(f"undecodable token: {e}") from e

    kid = claims.get("kid", "env")
    signer = get_signer(kid)
    try:
        signer.verify(payload, sig)
    except InvalidSignature as e:
        raise TokenError("invalid signature") from e

    # Required claims
    required = (
        "user_sub", "agent_id", "agent_instance_id", "tenant_id",
        "build_hash", "model_version", "session_id", "iat", "exp", "jti",
    )
    for k in required:
        if k not in claims:
            raise TokenError(f"missing claim: {k}")

    # Expiry (allow 5s clock skew)
    now = int(time.time())
    if claims["exp"] < now - 5:
        raise TokenError("token expired")
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
        identity_method="agent_token",
    )


def decode_claims_unverified(token: str) -> dict:
    """Decode claims without verifying signature. For diagnostics only."""
    payload_b64 = token.split(".", 1)[0]
    return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
