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
    """RFC 8414 Authorization Server Metadata.

    SHIELD_OAUTH_ISSUER_URL, when set, is the public URL of this server: the
    endpoints are built on it (behind a TLS proxy the request's own base URL is
    http) and it is the issuer, which RFC 8414 requires to equal the URL the
    metadata was fetched from. Unset, the response is exactly as before.
    """
    from core.mcp.resource import issuer_url
    base_url = issuer_url() or str(request.base_url).rstrip("/")
    return build_server_metadata(base_url)


@router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """RFC 9728 Protected Resource Metadata.

    Lets MCP clients (IDEs) discover that this deployment is an OAuth-protected
    resource and which authorization server issues its tokens. Prefers
    SHIELD_PUBLIC_BASE_URL so the advertised host is the public one behind a
    proxy, falling back to the request host.
    """
    base_url = (
        os.environ.get("SHIELD_PUBLIC_BASE_URL", "").strip().rstrip("/")
        or str(request.base_url).rstrip("/")
    )
    return {
        "resource": base_url,
        "authorization_servers": [base_url],
        "scopes_supported": ["shield", "guardrails", "agent"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/docs",
    }


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

    # Enforce EXACT redirect_uri match. A client with no registered redirect_uris
    # cannot use the authorization-code flow (a code must only ever be sent to a
    # pre-registered URL); an omitted redirect_uri defaults only when exactly one
    # is registered.
    if not client.redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "client has no registered redirect_uris"},
        )
    if redirect_uri:
        if redirect_uri not in client.redirect_uris:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "redirect_uri not registered"},
            )
    elif len(client.redirect_uris) == 1:
        redirect_uri = client.redirect_uris[0]
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "redirect_uri required"},
        )

    # MCP sign-in: the resource is a tenant-addressed gateway URL, so the person
    # signs in through that tenant's identity provider. Every other request
    # keeps the tenant-key consent below, unchanged.
    # Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.5)
    from core.mcp.resource import federated_login_enabled, parse_resource
    resource = params.get("resource", "")
    if federated_login_enabled() and parse_resource(resource):
        from api.routes_mcp_signin import begin_sign_in
        return await begin_sign_in(
            client=client, redirect_uri=redirect_uri, code_challenge=code_challenge,
            scope=scope, state=state, resource=resource)
    if not client.tenant_id:
        # A self-registered client has no tenant, so it can only be used to
        # sign a person in to a gateway URL (above), never with a tenant key.
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request",
                     "error_description": "this client can only sign in to an MCP gateway URL "
                                          "(pass resource=<gateway URL>)"},
        )

    # Resource-owner authorization (consent). Auto-approving with no login let a
    # stranger trade a code for a valid tenant token. Require the request to be
    # authenticated as the client's tenant (X-API-Key) before issuing a code,
    # unless an operator explicitly enables auto-approve for a trusted M2M
    # deployment via SHIELD_OAUTH_AUTO_APPROVE. (Pure M2M should instead use the
    # client_credentials grant with a client secret.)
    if os.environ.get("SHIELD_OAUTH_AUTO_APPROVE", "").strip().lower() in ("1", "true", "yes", "on"):
        user_sub = f"client:{client_id}"
    else:
        from storage.tenant_store import resolve_tenant_by_api_key
        api_key = request.headers.get("X-API-Key", "").strip()
        caller_tenant = resolve_tenant_by_api_key(api_key) if api_key else ""
        if not caller_tenant or caller_tenant != (client.tenant_id or "\x00"):
            return JSONResponse(
                status_code=401,
                content={"error": "access_denied",
                         "error_description": "login/consent required: present the tenant X-API-Key that owns this client"},
            )
        user_sub = f"tenant:{caller_tenant}"

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
            resource=body.get("resource", ""),
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

    elif grant_type == "client_credentials":
        return await _handle_client_credentials(body, request)

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


async def _handle_client_credentials(body: dict, request: Request) -> JSONResponse:
    """OAuth 2.0 client-credentials grant — the M2M path.

    A confidential client (registered with a secret and the client_credentials
    grant) presents client_id + client_secret and receives an access token bound
    to its own tenant. No user, no redirect, no browser — and crucially, the
    secret proves the caller is the legitimately-registered client, so a stranger
    cannot obtain a token.
    """
    from storage.oauth_store import get_client, verify_client_secret

    client_id = (body.get("client_id") or "").strip()
    client_secret = body.get("client_secret") or ""
    if not client_id or not client_secret:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "client_id and client_secret required"},
        )

    client = await get_client(client_id)
    if client is None or not client.client_secret_hash:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "unknown or non-confidential client"},
        )
    if not verify_client_secret(client_secret, client.client_secret_hash):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "invalid client credentials"},
        )
    if "client_credentials" not in (client.grant_types or []):
        return JSONResponse(
            status_code=400,
            content={"error": "unauthorized_client",
                     "error_description": "client is not authorized for the client_credentials grant"},
        )

    if client.principal_id:
        return _service_account_token(client, body)

    access_token = issue_access_token(
        client_id=client_id,
        scope=client.scope or "shield",
        tenant_id=client.tenant_id,
        user_sub=f"client:{client_id}",
    )
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 600,
        "scope": client.scope or "shield",
    })


def _service_account_token(client, body: dict) -> JSONResponse:
    """A client bound to a service account: the token names the account, with
    its roles, so the MCP gateway treats the caller as verified.

    Refused while the account is suspended or removed. With `resource` set to
    one of the tenant's gateway URLs (RFC 8707), the token is valid on that
    server only; otherwise it is tenant-wide, like any client-credentials token.
    Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (A3)
    """
    from core.mcp.resource import parse_resource
    from core.oauth.authz_server import _current_principal, _principal_claims

    principal = _current_principal(client.tenant_id, {"id": client.principal_id,
                                                      "type": "service_account"})
    if principal is None:
        return JSONResponse(status_code=400, content={
            "error": "invalid_grant", "error_description": "the service account is not active"})
    resource = (body.get("resource") or "").strip()
    audience = "shield-oauth"
    if resource:
        parsed = parse_resource(resource)
        if not parsed or parsed[0] != client.tenant_id:
            return JSONResponse(status_code=400, content={
                "error": "invalid_target",
                "error_description": "resource must be one of this organization's gateway URLs"})
        audience = resource
    token = issue_access_token(
        client_id=client.client_id, scope=client.scope or "mcp", tenant_id=client.tenant_id,
        user_sub=principal["id"], audience=audience,
        extra_claims=_principal_claims(principal))
    return JSONResponse(content={"access_token": token, "token_type": "Bearer",
                                 "expires_in": 600, "scope": client.scope or "mcp"})


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

    # Fail closed: token exchange must run in a resolved tenant context.
    # Without a tenant, the provider lookup below would fall back to the
    # empty-tenant namespace (get_provider_by_issuer("", issuer)), which
    # risks issuing an access token scoped to an empty/unintended tenant
    # and breaks per-tenant OIDC isolation. Reject rather than guess.
    if not tenant_id:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "tenant context required for token exchange",
            },
        )

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
