"""Standard JWT (RFC 7519) encoding and decoding with EdDSA (Ed25519).

Wraps the Signer protocol to produce and verify standard three-segment JWTs
(header.payload.signature) that any RFC-compliant JWT library can verify.

Also provides JWKS (JSON Web Key Set) construction for public key discovery.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.signers import Signer


class JWTError(Exception):
    """Raised when JWT encoding or decoding fails."""


# ── Base64url helpers (no padding, per RFC 7515) ────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ── JWT encode / decode ─────────────────────────────────────────────────


def encode_jwt(claims: dict, signer: Signer) -> str:
    """Encode claims into a signed JWT (EdDSA / Ed25519).

    Produces: base64url(header).base64url(payload).base64url(signature)
    """
    header = {"alg": "EdDSA", "typ": "JWT", "kid": signer.kid}
    header_b64 = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    payload_b64 = _b64url_encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = signer.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_jwt(
    token: str,
    signer: Signer,
    *,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    clock_skew_seconds: int = 5,
) -> dict:
    """Decode and verify a JWT signed with EdDSA.

    Checks: signature, exp (with clock skew), aud, iss.
    Returns the claims dict on success, raises JWTError on failure.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("malformed JWT: expected 3 segments")

    header_b64, payload_b64, sig_b64 = parts

    # Decode header
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        raise JWTError(f"invalid JWT header: {e}") from e

    if header.get("alg") != "EdDSA":
        raise JWTError(f"unsupported algorithm: {header.get('alg')}")

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        sig = _b64url_decode(sig_b64)
    except Exception as e:
        raise JWTError(f"invalid signature encoding: {e}") from e

    try:
        signer.verify(signing_input, sig)
    except InvalidSignature as e:
        raise JWTError("invalid signature") from e

    # Decode payload
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise JWTError(f"invalid JWT payload: {e}") from e

    # Check expiry
    now = int(time.time())
    if "exp" in claims and claims["exp"] < now - clock_skew_seconds:
        raise JWTError("token expired")

    # Check issuer
    if issuer is not None and claims.get("iss") != issuer:
        raise JWTError(f"issuer mismatch: {claims.get('iss')!r}")

    # Check audience
    if audience is not None and claims.get("aud") != audience:
        raise JWTError(f"audience mismatch: {claims.get('aud')!r}")

    return claims


def decode_jwt_unverified(token: str) -> dict:
    """Decode JWT claims WITHOUT verifying the signature.

    For diagnostics, logging, and extracting kid before verification only.
    """
    parts = token.split(".")
    if len(parts) == 3:
        # Standard JWT
        return json.loads(_b64url_decode(parts[1]))
    elif len(parts) == 2:
        # Legacy format: base64(claims).base64(sig)
        return json.loads(_b64url_decode(parts[0]))
    raise JWTError("unrecognized token format")


def is_jwt_format(token: str) -> bool:
    """Return True if the token looks like a standard JWT (3 dot-separated segments)."""
    return token.count(".") == 2


# ── JWKS helpers ────────────────────────────────────────────────────────


def build_jwk(signer: Signer) -> dict:
    """Build a JWK (JSON Web Key) dict from a signer's public key.

    Returns an OKP (Octet Key Pair) JWK for Ed25519.
    """
    pk_bytes = signer.public_key_bytes()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(pk_bytes),
        "kid": signer.kid,
        "use": "sig",
        "alg": "EdDSA",
    }


def build_jwks(signers: list[Signer]) -> dict:
    """Build a JWKS (JSON Web Key Set) from a list of signers."""
    return {"keys": [build_jwk(s) for s in signers]}
