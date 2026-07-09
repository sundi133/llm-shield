"""OIDC Relying Party -- validates id_tokens from external IdPs.

Supports Keycloak, Okta, Auth0, Azure AD, and any OpenID Connect provider
that publishes a standard .well-known/openid-configuration document.

No OIDC-specific library needed -- validation is done with PyJWT + httpx.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx
import jwt  # PyJWT
from jwt import PyJWKClient

from core.oauth.jwks_cache import get_jwks

logger = logging.getLogger("votal.oidc_client")


@dataclass
class OIDCProvider:
    """Configuration for a single external OIDC provider."""

    issuer: str  # e.g. "https://auth.example.com/realms/myapp"
    client_id: str  # Shield's client_id registered at the IdP
    audience: str = ""  # Expected aud claim (defaults to client_id)
    jwks_uri: str = ""  # Auto-discovered if empty
    claim_mapping: dict = field(default_factory=dict)
    # claim_mapping maps IdP claims to Shield claims, e.g.:
    # {"sub": "user_sub", "preferred_username": "agent_id"}

    def effective_audience(self) -> str:
        return self.audience or self.client_id


class OIDCValidationError(Exception):
    """Raised when an id_token fails validation."""


async def discover_openid_config(issuer: str) -> dict:
    """Fetch the OpenID Connect discovery document.

    Args:
        issuer: The issuer URL (e.g. "https://auth.example.com").

    Returns:
        The parsed JSON discovery document.
    """
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def _resolve_jwks_uri(provider: OIDCProvider) -> str:
    """Resolve the JWKS URI, auto-discovering if not configured."""
    if provider.jwks_uri:
        return provider.jwks_uri

    config = await discover_openid_config(provider.issuer)
    jwks_uri = config.get("jwks_uri", "")
    if not jwks_uri:
        raise OIDCValidationError(
            f"no jwks_uri in discovery document for {provider.issuer}"
        )
    return jwks_uri


async def validate_id_token(
    token: str,
    provider: OIDCProvider,
) -> dict:
    """Validate an id_token from an external OIDC provider.

    Checks:
    - Signature via the provider's JWKS
    - Issuer matches provider.issuer
    - Audience matches provider.client_id (or provider.audience)
    - Token is not expired

    Args:
        token: The raw JWT id_token string.
        provider: The OIDC provider configuration.

    Returns:
        The verified claims dict.

    Raises:
        OIDCValidationError: If validation fails.
    """
    try:
        jwks_uri = await _resolve_jwks_uri(provider)
        jwks_data = await get_jwks(provider.issuer, jwks_uri)
    except Exception as e:
        raise OIDCValidationError(f"JWKS fetch failed: {e}") from e

    # Decode the JWT header to find the kid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as e:
        raise OIDCValidationError(f"invalid token header: {e}") from e

    kid = unverified_header.get("kid")
    alg = unverified_header.get("alg", "RS256")

    # Find the matching key in JWKS
    matching_key = None
    for key_data in jwks_data.get("keys", []):
        if kid and key_data.get("kid") == kid:
            matching_key = key_data
            break
    if matching_key is None and len(jwks_data.get("keys", [])) == 1:
        # If only one key and no kid match, use it
        matching_key = jwks_data["keys"][0]
    if matching_key is None:
        raise OIDCValidationError(f"no matching key found for kid={kid}")

    # Convert JWK to a public key
    try:
        from jwt import PyJWK
        jwk = PyJWK(matching_key)
        public_key = jwk.key
    except Exception as e:
        raise OIDCValidationError(f"invalid JWK: {e}") from e

    # Verify and decode
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            issuer=provider.issuer,
            audience=provider.effective_audience(),
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise OIDCValidationError("id_token expired") from e
    except jwt.InvalidIssuerError as e:
        raise OIDCValidationError(f"issuer mismatch") from e
    except jwt.InvalidAudienceError as e:
        raise OIDCValidationError(f"audience mismatch") from e
    except jwt.exceptions.DecodeError as e:
        raise OIDCValidationError(f"invalid token: {e}") from e
    except Exception as e:
        raise OIDCValidationError(f"token validation failed: {e}") from e

    return claims


def map_claims(idp_claims: dict, mapping: dict) -> dict:
    """Transform IdP claims to Shield claims using a mapping.

    Args:
        idp_claims: Claims from the validated id_token.
        mapping: Dict mapping IdP claim names to Shield claim names.
            e.g. {"sub": "user_sub", "preferred_username": "agent_id"}

    Returns:
        Dict with Shield claim names and values from the IdP token.
    """
    result = {}
    for idp_key, shield_key in mapping.items():
        if idp_key in idp_claims:
            result[shield_key] = idp_claims[idp_key]

    # Always include sub -> user_sub if not explicitly mapped
    if "user_sub" not in result and "sub" in idp_claims:
        result["user_sub"] = idp_claims["sub"]

    return result


class OIDCProviderRegistry:
    """Per-tenant registry of configured OIDC providers.

    Loaded from Redis key shield:oidc:providers:{tenant_id}.
    """

    def __init__(self) -> None:
        self._providers: dict[str, dict[str, OIDCProvider]] = {}

    async def get_providers(self, tenant_id: str) -> dict[str, OIDCProvider]:
        """Get all OIDC providers for a tenant."""
        if tenant_id in self._providers:
            return self._providers[tenant_id]

        providers = await self._load_from_redis(tenant_id)
        self._providers[tenant_id] = providers
        return providers

    async def get_provider(
        self, tenant_id: str, provider_name: str
    ) -> Optional[OIDCProvider]:
        """Get a specific OIDC provider by name."""
        providers = await self.get_providers(tenant_id)
        return providers.get(provider_name)

    async def get_provider_by_issuer(
        self, tenant_id: str, issuer: str
    ) -> Optional[OIDCProvider]:
        """Find a provider by its issuer URL."""
        providers = await self.get_providers(tenant_id)
        for p in providers.values():
            if p.issuer.rstrip("/") == issuer.rstrip("/"):
                return p
        return None

    async def register_provider(
        self, tenant_id: str, name: str, provider: OIDCProvider
    ) -> None:
        """Register or update an OIDC provider for a tenant."""
        providers = await self.get_providers(tenant_id)
        providers[name] = provider
        self._providers[tenant_id] = providers
        await self._save_to_redis(tenant_id, providers)

    async def remove_provider(self, tenant_id: str, name: str) -> bool:
        """Remove an OIDC provider. Returns True if it existed."""
        providers = await self.get_providers(tenant_id)
        if name not in providers:
            return False
        del providers[name]
        self._providers[tenant_id] = providers
        await self._save_to_redis(tenant_id, providers)
        return True

    def invalidate_cache(self, tenant_id: str) -> None:
        """Clear cached providers for a tenant."""
        self._providers.pop(tenant_id, None)

    @staticmethod
    async def _load_from_redis(tenant_id: str) -> dict[str, OIDCProvider]:
        """Load providers from Redis."""
        try:
            from storage.tenant_store import _get_redis
            r = _get_redis()
            if r:
                raw = r.get(f"shield:oidc:providers:{tenant_id}")
                if raw:
                    data = json.loads(raw)
                    return {
                        name: OIDCProvider(**cfg) for name, cfg in data.items()
                    }
        except Exception as e:
            logger.warning(f"Failed to load OIDC providers from Redis: {e}")
        return {}

    @staticmethod
    async def _save_to_redis(
        tenant_id: str, providers: dict[str, OIDCProvider]
    ) -> None:
        """Save providers to Redis."""
        try:
            from storage.tenant_store import _get_redis
            r = _get_redis()
            if r:
                data = {
                    name: {
                        "issuer": p.issuer,
                        "client_id": p.client_id,
                        "audience": p.audience,
                        "jwks_uri": p.jwks_uri,
                        "claim_mapping": p.claim_mapping,
                    }
                    for name, p in providers.items()
                }
                r.set(f"shield:oidc:providers:{tenant_id}", json.dumps(data))
        except Exception as e:
            logger.warning(f"Failed to save OIDC providers to Redis: {e}")


# Module-level singleton
oidc_registry = OIDCProviderRegistry()
