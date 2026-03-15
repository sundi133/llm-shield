"""API key authentication middleware for LLM Shield."""

import hashlib
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import config.schema as _config_module


class AuthMiddleware(BaseHTTPMiddleware):
    """Validates API key on protected endpoints.

    Checks for API key in:
    1. Authorization: Bearer <key>
    2. X-API-Key: <key>

    Public paths (health, docs, playground) are exempted.
    When auth is disabled in config, all requests pass through.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        cfg = _config_module.config
        if cfg is None or not cfg.auth.enabled:
            return await call_next(request)

        # Check if path is public
        path = request.url.path
        for public in cfg.auth.public_paths:
            if path == public or path.startswith(public + "/"):
                return await call_next(request)

        # No keys configured means auth is misconfigured — reject
        if not cfg.auth.api_keys:
            return JSONResponse(
                status_code=500,
                content={"error": "Auth enabled but no API keys configured"},
            )

        # Extract key from request
        api_key = _extract_api_key(request)
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"error": "Missing API key. Use Authorization: Bearer <key> or X-API-Key header."},
            )

        # Validate key
        if not _validate_key(api_key, cfg.auth.api_keys):
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid API key"},
            )

        return await call_next(request)


def _extract_api_key(request: Request) -> str | None:
    """Extract API key from Authorization header or X-API-Key header."""
    # Check Authorization: Bearer <key>
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()

    return None


def _validate_key(provided: str, valid_keys: list[str]) -> bool:
    """Validate an API key against the list of valid keys.

    Supports both plaintext keys and SHA-256 hashed keys (prefixed with "sha256:").
    Uses constant-time comparison to prevent timing attacks.
    """
    provided_hash = hashlib.sha256(provided.encode()).hexdigest()

    for valid_key in valid_keys:
        if valid_key.startswith("sha256:"):
            # Compare against stored hash
            stored_hash = valid_key[7:]
            if hmac.compare_digest(provided_hash, stored_hash):
                return True
        else:
            # Compare plaintext with constant-time comparison
            if hmac.compare_digest(provided, valid_key):
                return True

    return False
