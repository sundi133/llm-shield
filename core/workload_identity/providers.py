"""Built-in workload-identity providers.

Each wraps an attestation method that already exists in the request path:
  - admin_key : the X-Admin-Key hmac check (unchanged from the legacy gate)
  - spiffe    : request.state.spiffe_identity, set by SPIFFEMiddleware
  - mtls      : request.state.mtls_identity, set by MTLSMiddleware

The spiffe/mtls providers only read identity the middleware already validated;
they add no verification of their own (and inherit its guarantees — see the
SPIFFE X.509 hardening note in docs/spec-modular-workload-identity.md).
"""

from __future__ import annotations

import functools
import hmac
import json
import logging
import os
import urllib.request
from typing import Optional

from starlette.requests import Request

from core.workload_identity.base import WorkloadIdentity

logger = logging.getLogger("votal.workload_identity")


class AdminKeyProvider:
    """Shared-secret admin key via the X-Admin-Key header. trust: medium."""

    name = "admin_key"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        admin_key = os.environ.get("SHIELD_ADMIN_KEY", "")
        if not admin_key:
            return None  # unconfigured -> cannot verify; registry handles the 500 signal
        provided = request.headers.get("X-Admin-Key", "").strip()
        if provided and hmac.compare_digest(provided, admin_key):
            return WorkloadIdentity(provider=self.name, subject="admin-key", trust_level="medium")
        return None


class SpiffeProvider:
    """SPIFFE identity already validated by SPIFFEMiddleware. trust: high*."""

    name = "spiffe"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        ident = getattr(request.state, "spiffe_identity", None) if hasattr(request, "state") else None
        if not ident:
            return None
        subject = ident.get("user_sub") or ident.get("agent_id") or "spiffe-workload"
        return WorkloadIdentity(
            provider=self.name,
            subject=subject,
            trust_level=ident.get("trust_level", "high"),
            claims=dict(ident),
        )


class MTLSProvider:
    """mTLS identity already validated by MTLSMiddleware. trust: high."""

    name = "mtls"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        ident = getattr(request.state, "mtls_identity", None) if hasattr(request, "state") else None
        if not ident:
            return None
        subject = ident.get("subject") or ident.get("cn") or ident.get("agent_id") or "mtls-workload"
        return WorkloadIdentity(
            provider=self.name,
            subject=subject,
            trust_level=ident.get("trust_level", "high"),
            claims=dict(ident),
        )


# ── oidc_sa: service-account / k8s-ServiceAccount JWT (the "no SPIFFE" path) ──

@functools.lru_cache(maxsize=32)
def _jwk_client(jwks_uri: str):
    from jwt import PyJWKClient
    return PyJWKClient(jwks_uri)


def _discover_jwks_uri(issuer: str) -> str:
    """Resolve an issuer's jwks_uri via OIDC discovery, or an env override.

    SHIELD_WORKLOAD_OIDC_JWKS lets you pin a jwks_uri directly (e.g. a k8s
    cluster that doesn't serve public discovery). Otherwise fetch
    <issuer>/.well-known/openid-configuration.
    """
    override = os.environ.get("SHIELD_WORKLOAD_OIDC_JWKS", "").strip()
    if override:
        return override
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (trusted issuer list)
        return json.load(resp)["jwks_uri"]


def _resolve_signing_key(issuer: str, token: str):
    """Return the verified signing key for a token. Patched in tests."""
    return _jwk_client(_discover_jwks_uri(issuer)).get_signing_key_from_jwt(token).key


class OIDCServiceAccountProvider:
    """Verify a service-account JWT (Bearer) against a trusted OIDC issuer.

    This is the path for deployments *without* SPIFFE: a Kubernetes cluster is an
    OIDC issuer, so a projected ServiceAccount token verifies here; likewise a
    corporate IdP client-credentials token for external callers.

    Config:
      SHIELD_WORKLOAD_OIDC_ISSUERS   comma list of trusted issuer URLs (required)
      SHIELD_WORKLOAD_OIDC_AUDIENCE  required audience (optional but recommended)
      SHIELD_WORKLOAD_OIDC_JWKS      pin a jwks_uri instead of discovery (optional)

    Trust: high when an audience is enforced (proves the token was minted for
    Shield), else medium.
    """

    name = "oidc_sa"

    def verify(self, request: Request) -> Optional[WorkloadIdentity]:
        import jwt as pyjwt

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()

        issuers = [i.strip() for i in os.environ.get("SHIELD_WORKLOAD_OIDC_ISSUERS", "").split(",") if i.strip()]
        if not issuers:
            return None
        audience = os.environ.get("SHIELD_WORKLOAD_OIDC_AUDIENCE", "").strip() or None

        # Read the issuer from the unverified token, then only trust it if allow-listed.
        try:
            iss = pyjwt.decode(token, options={"verify_signature": False}).get("iss", "")
        except Exception:
            return None
        if iss not in issuers:
            return None

        try:
            key = _resolve_signing_key(iss, token)
            claims = pyjwt.decode(
                token,
                key,
                algorithms=["RS256", "ES256"],
                audience=audience,
                options={"require": ["sub", "exp"], "verify_aud": audience is not None},
            )
        except Exception as exc:
            logger.debug("oidc_sa token rejected: %s", exc)
            return None

        return WorkloadIdentity(
            provider=self.name,
            subject=claims.get("sub", ""),
            trust_level="high" if audience else "medium",
            claims=claims,
        )
