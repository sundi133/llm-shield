"""OAuth 2.1 Authorization Server core logic.

Implements authorization code grant with PKCE, token issuance,
refresh token rotation, and client registration.

Works fully on-prem: no cloud dependencies. Uses Redis when available,
falls back to in-memory for single-worker deployments.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
import uuid
from typing import Optional

from core.jwt_utils import encode_jwt, build_jwk, build_jwks
from core.oauth.pkce import verify_code_challenge
from core.signers import Signer

logger = logging.getLogger("votal.oauth_authz")


# ── Token issuance ──────────────────────────────────────────────────────


def _get_oauth_signer() -> Signer:
    """Get the signer for OAuth access tokens.

    Reuses the agent token signer by default (same Ed25519 key),
    but can be overridden with SHIELD_SIGNER_BACKEND_OAUTH.
    """
    from core.agent_tokens import get_signer
    return get_signer()


def issue_access_token(
    *,
    client_id: str,
    scope: str,
    tenant_id: str,
    user_sub: str,
    ttl_seconds: int = 600,
    audience: str = "shield-oauth",
    extra_claims: Optional[dict] = None,
) -> str:
    """Mint a JWT access token for an OAuth client.

    The access token is a standard JWT verifiable by any library. `audience`
    defaults to the tenant-wide "shield-oauth"; a token from MCP sign-in names
    one gateway URL instead, so it is refused by every other server.
    """
    signer = _get_oauth_signer()
    now = int(time.time())
    claims = {
        **(extra_claims or {}),
        "iss": os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield",
        "aud": audience,
        "sub": user_sub,
        "client_id": client_id,
        "tenant_id": tenant_id,
        "scope": scope,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "kid": signer.kid,
        "token_type": "access_token",
    }
    return encode_jwt(claims, signer)


def issue_refresh_token() -> str:
    """Generate an opaque refresh token (not a JWT)."""
    return secrets.token_urlsafe(48)


# ── Client registration ────────────────────────────────────────────────


def generate_client_id() -> str:
    """Generate a unique client ID."""
    return f"shield-{uuid.uuid4().hex[:16]}"


def generate_client_secret() -> str:
    """Generate a client secret for confidential clients."""
    return secrets.token_urlsafe(32)


# ── Authorization code exchange ─────────────────────────────────────────


def _principal_claims(principal: dict) -> dict:
    """The claims a principal-naming access token carries (A2 of the spec)."""
    return {
        "ptype": principal.get("type", ""),
        "email": principal.get("email", ""),
        "roles": list(principal.get("roles") or []),
        "idp": principal.get("issuer", ""),
    }


def _current_principal(tenant_id: str, principal: dict) -> Optional[dict]:
    """The principal as stored now, or None if it is no longer active.

    A refresh must not outlive a suspension: the stored record, not the one
    captured at sign-in, decides. Roles and email come from it too, so a group
    change reaches the next token.
    """
    from storage.principal_store import get_principal, is_active
    doc = get_principal(tenant_id, principal.get("id", ""))
    if not is_active(doc) or doc.get("type") != principal.get("type"):
        return None
    return {"id": doc["id"], "type": doc["type"], "email": doc.get("email", ""),
            "roles": list(doc.get("roles") or []), "issuer": doc.get("issuer", "")}


async def exchange_authorization_code(
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str = "",
) -> dict:
    """Exchange an authorization code for tokens.

    Validates the code, PKCE verifier, client_id, and redirect_uri.
    Returns a token response dict.
    """
    from storage.oauth_store import consume_auth_code, save_refresh_token, RefreshTokenRecord

    auth_code = await consume_auth_code(code)
    if auth_code is None:
        return {"error": "invalid_grant", "error_description": "invalid or expired authorization code"}

    # Validate client_id
    if auth_code.client_id != client_id:
        return {"error": "invalid_grant", "error_description": "client_id mismatch"}

    # Validate redirect_uri
    if auth_code.redirect_uri != redirect_uri:
        return {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}

    # Validate PKCE
    if not verify_code_challenge(
        code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
    ):
        return {"error": "invalid_grant", "error_description": "PKCE verification failed"}

    # RFC 8707: a resource named at the token endpoint must be the one the
    # person consented to at the authorization endpoint.
    if resource and auth_code.resource and resource != auth_code.resource:
        return {"error": "invalid_target", "error_description": "resource does not match the authorization"}

    principal = auth_code.principal or {}
    if principal:
        principal = _current_principal(auth_code.tenant_id, principal)
        if principal is None:
            return {"error": "invalid_grant", "error_description": "account is not active"}

    # Issue tokens
    access_token = issue_access_token(
        client_id=client_id,
        scope=auth_code.scope,
        tenant_id=auth_code.tenant_id,
        user_sub=principal.get("id") if principal else auth_code.user_sub,
        audience=auth_code.resource or "shield-oauth",
        extra_claims=_principal_claims(principal) if principal else None,
    )

    refresh_token = issue_refresh_token()
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    await save_refresh_token(RefreshTokenRecord(
        token_hash=refresh_hash,
        client_id=client_id,
        scope=auth_code.scope,
        tenant_id=auth_code.tenant_id,
        user_sub=auth_code.user_sub,
        created_at=int(time.time()),
        resource=auth_code.resource,
        principal=principal or {},
    ))

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 600,
        "refresh_token": refresh_token,
        "scope": auth_code.scope,
    }


async def exchange_refresh_token(
    *,
    refresh_token: str,
    client_id: str,
) -> dict:
    """Exchange a refresh token for new tokens (rotation).

    The old refresh token is consumed and a new one is issued.
    """
    from storage.oauth_store import consume_refresh_token, save_refresh_token, RefreshTokenRecord

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    record = await consume_refresh_token(token_hash)
    if record is None:
        return {"error": "invalid_grant", "error_description": "invalid or expired refresh token"}

    if record.client_id != client_id:
        return {"error": "invalid_grant", "error_description": "client_id mismatch"}

    principal = record.principal or {}
    if principal:
        principal = _current_principal(record.tenant_id, principal)
        if principal is None:
            return {"error": "invalid_grant", "error_description": "account is not active"}

    # Issue new tokens
    access_token = issue_access_token(
        client_id=client_id,
        scope=record.scope,
        tenant_id=record.tenant_id,
        user_sub=principal.get("id") if principal else record.user_sub,
        audience=record.resource or "shield-oauth",
        extra_claims=_principal_claims(principal) if principal else None,
    )

    new_refresh = issue_refresh_token()
    new_hash = hashlib.sha256(new_refresh.encode()).hexdigest()
    await save_refresh_token(RefreshTokenRecord(
        token_hash=new_hash,
        client_id=client_id,
        scope=record.scope,
        tenant_id=record.tenant_id,
        user_sub=record.user_sub,
        created_at=int(time.time()),
        resource=record.resource,
        principal=principal or {},
    ))

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 600,
        "refresh_token": new_refresh,
        "scope": record.scope,
    }


# ── Server metadata ────────────────────────────────────────────────────


def build_server_metadata(base_url: str) -> dict:
    """Build OAuth 2.1 Authorization Server Metadata (RFC 8414)."""
    issuer = (os.environ.get("SHIELD_OAUTH_ISSUER_URL", "").strip().rstrip("/")
              or os.environ.get("SHIELD_ISSUER", "shield").strip() or "shield")
    base = base_url.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "jwks_uri": f"{base}/oauth/jwks",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "scopes_supported": ["shield", "guardrails", "agent"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": f"{base}/docs",
    }
