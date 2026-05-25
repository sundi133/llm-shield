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
    # Optional registration token gate
    reg_token = os.environ.get("SHIELD_OAUTH_REGISTRATION_TOKEN", "").strip()
    if reg_token:
        # Check Authorization header or body field
        auth_header = request.headers.get("Authorization", "")
        body_token = ""
        try:
            body = await request.json()
            body_token = body.get("initial_access_token", "")
        except Exception:
            body = {}

        bearer = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""
        if bearer != reg_token and body_token != reg_token:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": "valid registration token required"},
            )
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}

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

    # Resolve tenant from request state
    tenant_id = getattr(request.state, "tenant_id", "") or ""

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
