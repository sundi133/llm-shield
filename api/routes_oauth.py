"""OAuth 2.1 Authorization Server endpoints.

Implements the endpoints required by the MCP spec and RFC 8414:
- GET  /.well-known/oauth-authorization-server  -- Server metadata
- GET  /oauth/authorize                          -- Authorization endpoint
- POST /oauth/token                              -- Token endpoint
- GET  /oauth/jwks                               -- Public key set
- POST /oauth/revoke                             -- Token revocation

Works fully on-prem: no cloud dependencies.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from core.jwt_utils import build_jwks, decode_jwt, JWTError
from core.oauth.authz_server import (
    build_server_metadata,
    exchange_authorization_code,
    exchange_refresh_token,
    issue_access_token,
)
from core.oauth.pkce import generate_code_challenge

logger = logging.getLogger("votal.routes_oauth")
router = APIRouter(tags=["oauth"])


# ── Server metadata ────────────────────────────────────────────────────


@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """RFC 8414 Authorization Server Metadata."""
    base_url = str(request.base_url).rstrip("/")
    return build_server_metadata(base_url)


# ── JWKS endpoint ──────────────────────────────────────────────────────


@router.get("/oauth/jwks")
async def oauth_jwks():
    """Public keys for verifying tokens issued by this server."""
    from core.agent_tokens import get_signer
    signer = get_signer()
    return build_jwks([signer])


# ── Authorization endpoint ─────────────────────────────────────────────


@router.get("/oauth/authorize")
async def oauth_authorize(request: Request):
    """OAuth 2.1 authorization endpoint.

    Query params:
        response_type: Must be "code"
        client_id: Registered client ID
        redirect_uri: Must match registered URI
        code_challenge: PKCE S256 challenge
        code_challenge_method: Must be "S256"
        scope: Requested scope (default: "shield")
        state: Opaque state for CSRF protection
    """
    params = request.query_params
    response_type = params.get("response_type", "")
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")
    scope = params.get("scope", "shield")
    state = params.get("state", "")

    if response_type != "code":
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_response_type"},
        )

    if not client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "client_id required"},
        )

    if code_challenge_method != "S256":
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "only S256 code_challenge_method supported"},
        )

    if not code_challenge:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "code_challenge required (PKCE)"},
        )

    # Validate client
    from storage.oauth_store import get_client
    client = await get_client(client_id)
    if client is None:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_client", "error_description": "unknown client_id"},
        )

    # Validate redirect_uri against registered URIs
    if redirect_uri and client.redirect_uris and redirect_uri not in client.redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "redirect_uri not registered"},
        )
    if not redirect_uri and client.redirect_uris:
        redirect_uri = client.redirect_uris[0]

    # For MCP / machine-to-machine: auto-approve (no consent screen needed).
    # In a user-facing deployment, this would render a consent page.
    # The user_sub is derived from the tenant's admin identity.
    user_sub = f"client:{client_id}"

    # Issue authorization code
    from storage.oauth_store import save_auth_code, AuthorizationCode
    code = secrets.token_urlsafe(32)
    auth_code = AuthorizationCode(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        tenant_id=client.tenant_id,
        user_sub=user_sub,
        created_at=int(time.time()),
    )
    await save_auth_code(auth_code)

    # Redirect back with code
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"

    return RedirectResponse(url=location, status_code=302)


# ── Token endpoint ─────────────────────────────────────────────────────


@router.post("/oauth/token")
async def oauth_token(request: Request):
    """OAuth 2.1 token endpoint.

    Handles:
    - grant_type=authorization_code (with PKCE)
    - grant_type=refresh_token
    - grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693)
    """
    # Accept both form-encoded and JSON
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type", "")

    if grant_type == "authorization_code":
        result = await exchange_authorization_code(
            code=body.get("code", ""),
            client_id=body.get("client_id", ""),
            redirect_uri=body.get("redirect_uri", ""),
            code_verifier=body.get("code_verifier", ""),
        )
        if "error" in result:
            return JSONResponse(status_code=400, content=result)
        return result

    elif grant_type == "refresh_token":
        result = await exchange_refresh_token(
            refresh_token=body.get("refresh_token", ""),
            client_id=body.get("client_id", ""),
        )
        if "error" in result:
            return JSONResponse(status_code=400, content=result)
        return result

    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        return await _handle_token_exchange(body, request)

    else:
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_grant_type",
                "error_description": f"unsupported grant_type: {grant_type}",
            },
        )


async def _handle_token_exchange(body: dict, request: Request) -> JSONResponse:
    """Handle RFC 8693 token exchange.

    Exchanges an external IdP id_token for a Shield access token.
    """
    subject_token = body.get("subject_token", "")
    subject_token_type = body.get("subject_token_type", "")
    scope = body.get("scope", "shield")
    audience = body.get("audience", "")

    if not subject_token:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "subject_token required"},
        )

    if subject_token_type not in (
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:jwt",
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "subject_token_type must be id_token or jwt",
            },
        )

    # Determine tenant from request context or audience
    tenant_id = getattr(request.state, "tenant_id", "") or ""

    # Validate the external token via OIDC client
    try:
        from core.oauth.oidc_client import oidc_registry, validate_id_token, map_claims
        from core.jwt_utils import decode_jwt_unverified

        # Extract issuer from the token to find the right provider
        unverified = decode_jwt_unverified(subject_token)
        token_issuer = unverified.get("iss", "")

        if not token_issuer:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "token has no issuer"},
            )

        # Find provider by issuer
        provider = await oidc_registry.get_provider_by_issuer(tenant_id, token_issuer)
        if provider is None:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": f"no OIDC provider registered for issuer {token_issuer}",
                },
            )

        # Validate the external token
        validated_claims = await validate_id_token(subject_token, provider)
        mapped = map_claims(validated_claims, provider.claim_mapping)

    except Exception as e:
        logger.warning(f"Token exchange failed: {e}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": str(e)},
        )

    # Issue Shield access token
    user_sub = mapped.get("user_sub", validated_claims.get("sub", ""))
    access_token = issue_access_token(
        client_id=f"exchange:{token_issuer}",
        scope=scope,
        tenant_id=tenant_id,
        user_sub=user_sub,
    )

    return JSONResponse(content={
        "access_token": access_token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 600,
        "scope": scope,
    })


# ── Token revocation ───────────────────────────────────────────────────


@router.post("/oauth/revoke")
async def oauth_revoke(request: Request):
    """RFC 7009 token revocation."""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    token = body.get("token", "")
    token_type_hint = body.get("token_type_hint", "")

    if not token:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request"},
        )

    if token_type_hint in ("refresh_token", ""):
        from storage.oauth_store import revoke_refresh_token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        await revoke_refresh_token(token_hash)

    # For access tokens (JWTs), we can add the jti to the revocation list
    if token_type_hint in ("access_token", ""):
        try:
            unverified = decode_jwt(token, _get_oauth_signer_for_verify(), clock_skew_seconds=3600)
            jti = unverified.get("jti")
            if jti:
                from storage.revocation import revoke_jti
                revoke_jti(jti)
        except Exception:
            pass  # Token might already be invalid; that's fine

    # RFC 7009: always return 200 even if token wasn't found
    return JSONResponse(content={})


def _get_oauth_signer_for_verify():
    from core.agent_tokens import get_signer
    return get_signer()
