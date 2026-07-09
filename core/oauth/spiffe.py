"""SPIFFE workload identity validation.

Accepts SPIFFE SVIDs (JWT or X.509) as workload identity for
agent token issuance, replacing admin-key auth for automated workloads.

On-prem friendly: trust bundles are loaded from local files.
No SPIRE agent required -- just the trust bundle and SVID.

SPIFFE ID format: spiffe://trust-domain/workload-path
Example: spiffe://prod.shield.local/billing-bot/v2
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import jwt as pyjwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ExtensionNotFound

logger = logging.getLogger("votal.spiffe")


@dataclass
class SPIFFETrustDomain:
    """Configuration for a SPIFFE trust domain."""
    trust_domain: str  # e.g. "prod.shield.local"
    jwks_uri: str = ""  # For JWT SVIDs (remote or local file)
    trust_bundle_path: str = ""  # For X.509 SVIDs (local CA cert path)
    allowed_workloads: list[str] = field(default_factory=list)


class SPIFFEValidationError(Exception):
    """Raised when SPIFFE SVID validation fails."""


def parse_spiffe_id(spiffe_id: str) -> tuple[str, str]:
    """Parse a SPIFFE ID into (trust_domain, workload_path).

    Args:
        spiffe_id: e.g. "spiffe://prod.shield.local/billing-bot/v2"

    Returns:
        Tuple of (trust_domain, workload_path).
    """
    if not spiffe_id.startswith("spiffe://"):
        raise SPIFFEValidationError(f"invalid SPIFFE ID: {spiffe_id}")
    rest = spiffe_id[len("spiffe://"):]
    if "/" in rest:
        domain, path = rest.split("/", 1)
        return domain, "/" + path
    return rest, "/"


async def validate_jwt_svid(
    token: str,
    trust_domain: SPIFFETrustDomain,
) -> dict:
    """Validate a SPIFFE JWT SVID.

    Args:
        token: The JWT SVID string.
        trust_domain: Trust domain configuration.

    Returns:
        The validated claims dict.
    """
    if not trust_domain.jwks_uri:
        raise SPIFFEValidationError(
            f"no jwks_uri configured for trust domain {trust_domain.trust_domain}"
        )

    # Load JWKS -- support local file paths (on-prem) and URLs
    jwks_uri = trust_domain.jwks_uri
    if jwks_uri.startswith("file://") or jwks_uri.startswith("/"):
        # Local JWKS file
        path = jwks_uri.replace("file://", "")
        try:
            with open(path) as f:
                jwks_data = json.load(f)
        except Exception as e:
            raise SPIFFEValidationError(f"failed to read JWKS file: {e}") from e
    else:
        # Remote JWKS URI
        from core.oauth.jwks_cache import get_jwks
        jwks_data = await get_jwks(
            f"spiffe://{trust_domain.trust_domain}",
            jwks_uri,
        )

    # Decode header to find kid and algorithm
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.exceptions.DecodeError as e:
        raise SPIFFEValidationError(f"invalid SVID header: {e}") from e

    kid = header.get("kid")
    alg = header.get("alg", "RS256")

    # Find matching key
    matching_key = None
    for key_data in jwks_data.get("keys", []):
        if kid and key_data.get("kid") == kid:
            matching_key = key_data
            break
    if matching_key is None and len(jwks_data.get("keys", [])) == 1:
        matching_key = jwks_data["keys"][0]
    if matching_key is None:
        raise SPIFFEValidationError(f"no matching key for kid={kid}")

    # Verify and decode
    try:
        from jwt import PyJWK
        jwk = PyJWK(matching_key)
        claims = pyjwt.decode(
            token,
            jwk.key,
            algorithms=[alg],
            options={"require": ["sub", "exp", "aud"]},
            audience=f"spiffe://{trust_domain.trust_domain}",
        )
    except pyjwt.ExpiredSignatureError:
        raise SPIFFEValidationError("JWT SVID expired")
    except Exception as e:
        raise SPIFFEValidationError(f"JWT SVID validation failed: {e}") from e

    # Validate SPIFFE ID from sub claim
    spiffe_id = claims.get("sub", "")
    domain, _ = parse_spiffe_id(spiffe_id)
    if domain != trust_domain.trust_domain:
        raise SPIFFEValidationError(
            f"trust domain mismatch: {domain} != {trust_domain.trust_domain}"
        )

    # Check allowlist
    if trust_domain.allowed_workloads:
        if spiffe_id not in trust_domain.allowed_workloads:
            raise SPIFFEValidationError(
                f"workload {spiffe_id} not in allowed list"
            )

    return claims


def validate_x509_svid(
    cert_pem: str,
    trust_domain: SPIFFETrustDomain,
) -> str:
    """Validate a SPIFFE X.509 SVID and extract the SPIFFE ID.

    Args:
        cert_pem: PEM-encoded client certificate.
        trust_domain: Trust domain configuration (needs trust_bundle_path).

    Returns:
        The SPIFFE ID from the certificate's SAN URI.
    """
    if not trust_domain.trust_bundle_path:
        raise SPIFFEValidationError(
            f"no trust_bundle_path for trust domain {trust_domain.trust_domain}"
        )

    # Load trust bundle (CA certificates)
    try:
        with open(trust_domain.trust_bundle_path, "rb") as f:
            trust_bundle_pem = f.read()
    except Exception as e:
        raise SPIFFEValidationError(f"failed to read trust bundle: {e}") from e

    # Parse the client certificate
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    except Exception as e:
        raise SPIFFEValidationError(f"invalid certificate: {e}") from e

    # Extract SPIFFE ID from Subject Alternative Name (URI)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    except ExtensionNotFound:
        raise SPIFFEValidationError("certificate has no Subject Alternative Name")

    spiffe_id = None
    for uri in uris:
        if uri.startswith("spiffe://"):
            spiffe_id = uri
            break

    if not spiffe_id:
        raise SPIFFEValidationError("no SPIFFE ID found in certificate SAN")

    # Validate trust domain
    domain, _ = parse_spiffe_id(spiffe_id)
    if domain != trust_domain.trust_domain:
        raise SPIFFEValidationError(
            f"trust domain mismatch: {domain} != {trust_domain.trust_domain}"
        )

    # Verify certificate chain against trust bundle
    # Note: Full chain verification requires the trust bundle CA certs.
    # For production, use a proper PKI verification library or SPIRE.
    # Here we do basic issuer check.
    try:
        ca_certs = x509.load_pem_x509_certificates(trust_bundle_pem)
        cert_issuer = cert.issuer
        trusted = any(ca.subject == cert_issuer for ca in ca_certs)
        if not trusted:
            raise SPIFFEValidationError("certificate issuer not in trust bundle")
    except SPIFFEValidationError:
        raise
    except Exception as e:
        raise SPIFFEValidationError(f"certificate chain verification failed: {e}") from e

    # Check allowlist
    if trust_domain.allowed_workloads:
        if spiffe_id not in trust_domain.allowed_workloads:
            raise SPIFFEValidationError(
                f"workload {spiffe_id} not in allowed list"
            )

    return spiffe_id


def spiffe_id_to_identity(spiffe_id: str, tenant_id: str) -> dict:
    """Map a SPIFFE ID to Shield identity claims.

    Extracts agent_id from the workload path.
    Example: spiffe://prod.local/billing-bot/v2 -> agent_id="billing-bot-v2"
    """
    _, path = parse_spiffe_id(spiffe_id)
    # Convert path to agent_id: /billing-bot/v2 -> billing-bot-v2
    agent_id = path.strip("/").replace("/", "-") or "spiffe-workload"
    return {
        "user_sub": spiffe_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "identity_method": "spiffe",
        "trust_level": "high",
    }
