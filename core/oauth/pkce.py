"""PKCE (Proof Key for Code Exchange) per RFC 7636.

Used by the OAuth 2.1 authorization flow for MCP clients.
No external dependencies -- stdlib hashlib + secrets only.
"""

from __future__ import annotations

import hashlib
import base64
import secrets
import string


# RFC 7636 section 4.1: unreserved characters
_UNRESERVED = string.ascii_letters + string.digits + "-._~"


def generate_code_verifier(length: int = 128) -> str:
    """Generate a cryptographically random code verifier.

    Args:
        length: Number of characters (43-128 per RFC 7636).

    Returns:
        A random string of unreserved characters.
    """
    if not (43 <= length <= 128):
        raise ValueError(f"code_verifier length must be 43-128, got {length}")
    return "".join(secrets.choice(_UNRESERVED) for _ in range(length))


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """Generate a code challenge from a code verifier.

    Args:
        verifier: The code verifier string.
        method: "S256" (SHA-256, recommended) or "plain".

    Returns:
        The code challenge string.
    """
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    elif method == "plain":
        return verifier
    else:
        raise ValueError(f"unsupported PKCE method: {method}")


def verify_code_challenge(
    verifier: str, challenge: str, method: str = "S256"
) -> bool:
    """Verify that a code verifier matches the stored code challenge.

    Args:
        verifier: The code verifier sent in the token request.
        challenge: The code challenge stored from the authorization request.
        method: The challenge method ("S256" or "plain").

    Returns:
        True if the verifier matches the challenge.
    """
    expected = generate_code_challenge(verifier, method)
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(expected, challenge)
