"""Dynamic Client Registration per RFC 7591.

Allows MCP clients to register themselves dynamically.
Optionally gated by an initial_access_token in production.
"""

from __future__ import annotations

import logging
import os
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.oauth.authz_server import generate_client_id, generate_client_secret
from storage.oauth_store import OAuthClient, hash_client_secret, save_client

logger = logging.getLogger("votal.routes_oauth_registration")
router = APIRouter(tags=["oauth-registration"])


def _is_allowed_redirect_uri(uri: str) -> bool:
    """Allow only exact https redirect URLs (http permitted for localhost dev).

    Rejects empty/relative/non-http(s) URIs and arbitrary http hosts so an
    authorization code can never be delivered to an attacker-controlled URL.
    """
    from urllib.parse import urlparse
    try:
        p = urlparse(uri)
    except Exception:
        return False
    if not p.scheme or not p.netloc:
        return False
    if p.scheme == "https":
        return True
    if p.scheme == "http" and (p.hostname in ("localhost", "127.0.0.1", "::1")):
        return True
    return False


@router.post("/oauth/register")
async def register_client(request: Request):
    """RFC 7591 Dynamic Client Registration.

    Body (JSON):
        client_name: Human-readable name
        redirect_uris: List of allowed redirect URIs
        grant_types: List of grant types (default: ["authorization_code", "refresh_token"])
        token_endpoint_auth_method: "none" (public) or "client_secret_post"
        scope: Requested scope (default: "shield")

    Optional:
        initial_access_token: Registration token (required if SHIELD_OAUTH_REGISTRATION_TOKEN is set)

    Returns:
        client_id, client_secret (if confidential), client_name, etc.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    # ── Authentication (was: none — anyone could register a client) ──────
    # Registration must be authenticated so every client is bound to a real
    # tenant. Accept a tenant API key (X-API-Key), and additionally require the
    # operator registration token when SHIELD_OAUTH_REGISTRATION_TOKEN is set.
    reg_token = os.environ.get("SHIELD_OAUTH_REGISTRATION_TOKEN", "").strip()
    if reg_token:
        auth_header = request.headers.get("Authorization", "")
        bearer = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        body_token = body.get("initial_access_token", "") if isinstance(body, dict) else ""
        if bearer != reg_token and body_token != reg_token:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": "valid registration token required"},
            )

    from storage.tenant_store import resolve_tenant_by_api_key
    api_key = request.headers.get("X-API-Key", "").strip()
    tenant_id = (getattr(request.state, "tenant_id", "") or "")
    if not tenant_id and api_key:
        tenant_id = resolve_tenant_by_api_key(api_key) or ""
    if not tenant_id:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_token",
                     "error_description": "registration requires a valid tenant X-API-Key"},
        )

    client_name = body.get("client_name", "").strip()
    if not client_name:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_client_metadata", "error_description": "client_name required"},
        )

    redirect_uris = body.get("redirect_uris", [])
    grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
    auth_method = body.get("token_endpoint_auth_method", "none")
    scope = body.get("scope", "shield")

    # Validate redirect URIs for any client that uses the authorization-code
    # flow: must be a non-empty list of exact https URLs (localhost may use http
    # for local dev). This blocks the "code sent to any attacker URL" path.
    if "authorization_code" in (grant_types or []):
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_redirect_uri",
                         "error_description": "redirect_uris required for authorization_code clients"},
            )
        for uri in redirect_uris:
            if not isinstance(uri, str) or not _is_allowed_redirect_uri(uri):
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_redirect_uri",
                             "error_description": f"redirect_uri must be an https URL (or http://localhost): {uri!r}"},
                )

    # Generate credentials
    client_id = generate_client_id()
    client_secret = None
    client_secret_hash = ""
    if auth_method == "client_secret_post":
        client_secret = generate_client_secret()
        client_secret_hash = hash_client_secret(client_secret)

    client = OAuthClient(
        client_id=client_id,
        client_name=client_name,
        client_secret_hash=client_secret_hash,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        token_endpoint_auth_method=auth_method,
        scope=scope,
        tenant_id=tenant_id,
        created_at=int(time.time()),
    )
    await save_client(client)

    response = {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "token_endpoint_auth_method": auth_method,
        "scope": scope,
    }
    if client_secret:
        response["client_secret"] = client_secret

    return JSONResponse(status_code=201, content=response)
